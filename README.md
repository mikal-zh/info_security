# Onboarding Vault

Information Security, Assignment 1. A web application where new employees of a
company store their onboarding file (personal data form, scanned KTP, contract
and CV, recorded interview video) encrypted at rest. Every item is stored three
times, sealed with **AES-256-CBC**, **DES-CBC** and **RC4-drop3072**, each copy
authenticated with HMAC-SHA256. Only the logged-in employee can retrieve their
own data, and a copy that fails its integrity check is never returned.

The report is in [docs/REPORT.pdf](docs/REPORT.pdf) (source: [docs/report.html](docs/report.html)).

## Run it

```bash
pip install -r requirements.txt
python scripts/seed_demo.py      # optional: demo employee emp-0001 / onboarding-2026
python run.py                    # http://127.0.0.1:5000
```

The seed script needs `ffmpeg` to generate the demo interview video; without
it, the video is skipped. Runtime data (SQLite database and encrypted files)
goes to `instance/`, which is not committed. Delete that folder to start over.

## Tests

```bash
python -m pytest -q
```

`tests/test_crypto.py` covers the cipher layer: round-trips, a fresh IV or
nonce per message, tamper and context-swap detection, and key wrapping.
`tests/test_app.py` covers the web app end to end: no plaintext or filenames
at rest, bit-exact retrieval from each copy, a tampered copy being refused,
cross-user access, CSRF, cookie contents, password change and erasure.

## Benchmark

```bash
taskset -c 2 python benchmark/run_benchmark.py   # ~2 min; --quick for a smoke test
```

Writes `benchmark/results/results.json`, `ciphers.csv` and `download.csv`.
The committed results are the ones used in the report.

## Layout

```text
run.py                    start the development server
hrvault/
  crypto/ciphers.py       AES-CBC, DES-CBC, RC4-drop3072 primitives
  crypto/envelope.py      encrypt-then-MAC envelope (HMAC-SHA256, context binding)
  crypto/keys.py          PBKDF2 login secrets, vault-key wrapping, per-cipher subkeys
  catalog.py              stored fields and document types, with their UU PDP / GDPR classification
  vault.py                store, retrieve, verify and delete personal data and documents
  accounts.py             register, login, password change
  keystore.py             in-memory store of unwrapped keys for logged-in users
  routes.py               Flask views
  db.py, config.py
  templates/
scripts/seed_demo.py      demo employee with a KTP scan, a .docx contract and an .mp4 video
benchmark/                benchmark script and committed results
tests/                    pytest suite
docs/                     report (HTML source and PDF)
```

To rebuild the PDF after editing the report:

```bash
google-chrome --headless=new --no-pdf-header-footer --print-to-pdf=docs/REPORT.pdf "file://$PWD/docs/report.html"
```
