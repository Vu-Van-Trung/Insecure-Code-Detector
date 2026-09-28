# Secure Code Analyzer

A Static Application Security Testing (SAST) tool for Python. It parses source
code with the `ast` module and runs pluggable security rules over the tree.
Analyzed code is **never executed**. It is only read as text and parsed.

> Status: Phase 1 (core infrastructure). Security rules, taint tracking, the web UI
> and reports are added in later phases. This README will be completed in Phase 9.

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

## CLI

```bash
python main.py scan path/to/file.py
python main.py scan ./project
python main.py scan ./project --format json -o report.json
python main.py rules
```

Exit codes: `0` means no findings, `1` means findings were reported, and `2`
means a usage error such as a missing target.

## Tests

```bash
python -m pytest
```
