# Reading the Hub without downloading it: Rangefetch Deep Dive

A Hub-scale false-positive measurement is bounded by download volume, not by
scan time. Scanning a large sample of public checkpoints the obvious way means
tens of terabytes. But a torch checkpoint is a zip whose tensor storage is
almost all of it, and the pickle that decides what executes on load is one
small member, so HTTP range requests can read that member and leave the
weights on the server. `quickset/rangefetch.py` does this;
`scripts/range_compare.py` is the reason to believe it.

What the fetcher writes is **not a fragment handed to the scanner**. It is a
sparse local copy of the remote file: the same filename, the same total
length, the fetched ranges written at their true offsets, and holes everywhere
else. The scanner is then pointed at that path and runs its ordinary code over
it. Nothing about zip parsing, magic sniffing, extension dispatch or the
scanner's own size limits is reimplemented in the fetcher, so none of it can
drift out of agreement with the scanner later.

| Format | What is read |
|---|---|
| torch zip (`PK`) | end-of-central-directory, the central directory, then per member its local header, its trailing data descriptor and its first 64 KB, then in full only the members a scanner parses |
| torch legacy (`\x80`) | a prefix grown until every pickle stream in it has reached STOP and the bytes after the last one are plainly not another pickle |
| SafeTensors | the 8-byte length prefix, the JSON header, and 64 KB past it |
| GGUF | the header, the KV metadata and the tensor-info table |
| any flat format past hayward's 500 MB in-memory cap | nothing past the first 4 KB, because the scanner reads nothing either and reports non-coverage from the size alone |
| ONNX, Keras, TFLite, skops, npz, joblib, msgpack, ... | downloaded whole, or recorded as **not sampled** above the size limit |

**Counting pickle streams is the mistake the legacy strategy exists to avoid.**
`torch.save`'s legacy path writes *five* of them (magic number, protocol
version, `sys_info`, the object, and the sorted storage-key list) before a byte
of tensor data, not the four that a reading of the format suggests. A prefix
cut after the fourth ends mid-stream, and hayward reports MFV-SKIP-003
when it sees one. So the fetcher does not count: it grows the prefix until the
bytes following the last completed stream are no longer a pickle. Any
unexplained MFV-SKIP-003 in a range-fetched run is a bug in the fetcher, not a
property of the model.

**A format with no range strategy is downloaded or recorded, never dropped.**
An omitted file does not lower a false-positive rate honestly, it corrupts the
denominator, which is the only thing the exercise produces.

### The gate

A fetcher that is 99% right is useless here, because the output is a rate and
the errors land directly in it rather than averaging out. So every sampled
file is scanned twice, once against the sparse range-fetched copy and once
against the whole file downloaded from the same URL in the same run, and
findings are compared verbatim: rule id, severity and message text.

```bash
python scripts/range_compare.py --sample 260 --max-size 150000000
```

Measured against live Hub repositories, on 260 files from 178 repositories:

```
compared    260
DIVERGED    0
not sampled 0
errored     0

strategy         files    read              of                share
------------------------------------------------------------------
full-small          77       2.5 MB          0.002 GB      100.00%
full                77    3026.2 MB          3.026 GB      100.00%
full-fallback        6     152.1 MB          0.152 GB      100.00%
torch-zip           27     128.0 MB          0.419 GB       30.55%
torch-legacy        22     126.6 MB          0.947 GB       13.37%
gguf                12      50.4 MB          0.649 GB        7.76%
safetensors         39       2.9 MB          0.855 GB        0.33%
------------------------------------------------------------------
range strategies   100     307.9 MB          2.870 GB       10.73%
```

### The gate across scanners

```
scanner       models  sparse  verdicts  on sparse  diverged  detail  gate
picklescan       260      86       218         83         0       0  PASS
modelscan        260      86        90         37         0       0  PASS
modelaudit       260      86       260         86         0       0  PASS
fickling         260      86       106         34         0       0  PASS
hayward          260      86       260         86         0       0  PASS
```

**One gap is real and this design does not close it.** A whole-buffer pass
over a region that was never fetched reads zeros. Whole-buffer binary scans
(such as embedded-executable scans) run over fetched bytes (container headers,
pickle members, metadata). A binary stapled into a pickle member is still found;
one buried in raw tensor data between two fetched ranges is not. That is a
property of range reading, not of this implementation.
