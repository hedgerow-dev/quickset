"""Stage 1: size the pickle-bearing population on the Hub.

Metadata only. No file contents are fetched. Writes one JSONL line per repo
that carries at least one file hayward can read, plus a running total of every
repo seen so the denominator is real rather than inferred.

Resumable: the cursor is checkpointed, so an interrupted run continues.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from huggingface_hub import get_token

OUT_DIR = Path(__file__).parent / "stage1"
OUT_DIR.mkdir(exist_ok=True)
REPOS = OUT_DIR / "pickle_bearing.jsonl"
STATE = OUT_DIR / "cursor.json"

PAGE = 1000
DELAY = 0.15  # polite, well under any documented limit
MAX_RETRIES = 5

# hayward 1.0.1's readable set, plus the two it resolves by content sniff.
EXTENSIONS = {
    ".pkl", ".pickle", ".pth", ".pt", ".ckpt", ".joblib", ".npy", ".npz",
    ".mar", ".nemo", ".skops", ".safetensors", ".gguf", ".tflite", ".onnx",
    ".pb", ".h5", ".hdf5", ".keras", ".pmml", ".model", ".sav", ".dill",
    ".th", ".bin", ".zip",
}

# The subset that can actually carry a pickle. A safetensors-only repo is
# interesting for the census but cannot execute code on load.
PICKLE_EXTENSIONS = {
    ".pkl", ".pickle", ".pth", ".pt", ".ckpt", ".joblib", ".npy", ".npz",
    ".mar", ".nemo", ".skops", ".dill", ".th", ".sav", ".bin", ".zip",
}


def fetch(url, headers):
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read()), r.headers.get("Link", "")
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504):
                wait = 2 ** attempt
                print(f"  HTTP {exc.code}, backing off {wait}s", flush=True)
                time.sleep(wait)
                continue
            raise
        except Exception as exc:
            wait = 2 ** attempt
            print(f"  {type(exc).__name__}: {exc}, retry in {wait}s", flush=True)
            time.sleep(wait)
    raise RuntimeError(f"gave up after {MAX_RETRIES} retries: {url}")


def next_cursor(link_header):
    # RFC 5988: <url>; rel="next"
    for part in link_header.split(","):
        if 'rel="next"' in part:
            url = part.split(">")[0].strip().lstrip("<")
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            return query.get("cursor", [None])[0]
    return None


def main():
    token = get_token()
    headers = {"User-Agent": "hedgerow-hayward-survey/1.0 (hello@hedgerow.dev)"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        print("authenticated", flush=True)
    else:
        print("no stored token, running anonymous", flush=True)

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    cursor = state.get("cursor")
    seen = state.get("seen", 0)
    kept = state.get("kept", 0)
    mode = "a" if cursor else "w"
    started = time.monotonic()

    with REPOS.open(mode) as out:
        while True:
            params = {"limit": PAGE, "full": "true"}
            if cursor:
                params["cursor"] = cursor
            url = "https://huggingface.co/api/models?" + urllib.parse.urlencode(params)

            records, link = fetch(url, headers)
            if not records:
                break

            for rec in records:
                seen += 1
                files = [s["rfilename"] for s in rec.get("siblings") or []]
                readable = [f for f in files if _ext(f) in EXTENSIONS]
                pickle_bearing = [f for f in files if _ext(f) in PICKLE_EXTENSIONS]
                if not readable:
                    continue
                kept += 1
                out.write(json.dumps({
                    "id": rec["id"],
                    "sha": rec.get("sha"),
                    "downloads": rec.get("downloads", 0),
                    "likes": rec.get("likes", 0),
                    "gated": rec.get("gated", False),
                    "readable": readable,
                    "pickle_bearing": pickle_bearing,
                }) + "\n")

            out.flush()
            cursor = next_cursor(link)
            STATE.write_text(json.dumps({"cursor": cursor, "seen": seen, "kept": kept}))

            rate = seen / max(1e-9, time.monotonic() - started)
            print(f"seen {seen:,} | readable {kept:,} | {rate:.0f}/s", flush=True)

            if not cursor:
                break
            time.sleep(DELAY)

    print(f"\nDONE: {seen:,} repos seen, {kept:,} with a readable file", flush=True)


def _ext(name):
    dot = name.rfind(".")
    return name[dot:].lower() if dot != -1 else ""


if __name__ == "__main__":
    sys.exit(main())
