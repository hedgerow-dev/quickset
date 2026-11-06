#!/bin/sh
# Build one virtual environment per scanner at the versions used on
# 5 November 2026, plus one for quickset, and put the scanner commands on PATH.
# Run from the quickset checkout (git checkout a51d9f8 first).
# Transitive dependencies were not locked for that run, so they may differ.
set -e
mkdir -p "$HOME/qs-venvs" "$HOME/qs-venvs/bin"
python3 -m venv "$HOME/qs-venvs/quickset"
"$HOME/qs-venvs/quickset/bin/pip" install -q -e .
for spec in hayward==1.16.1 picklescan==1.0.5 modelscan==0.8.8 fickling==0.1.13 modelaudit==0.2.54; do
  name=${spec%%==*}
  python3 -m venv "$HOME/qs-venvs/$name"
  "$HOME/qs-venvs/$name/bin/pip" install -q "$spec"
  ln -sf "$HOME/qs-venvs/$name/bin/$name" "$HOME/qs-venvs/bin/$name"
done
echo "Now run: export PATH=\$HOME/qs-venvs/bin:\$PATH; source \$HOME/qs-venvs/quickset/bin/activate"
