<!--
  PROJECT, 2026
  info_security
  File description:
  Project overview, usage and layout.
-->

# Onboarding Vault

Information Security, Assignment 1. A web application where new employees
of a company store their onboarding file (personal data form, scanned KTP,
contract and CV, recorded interview video) encrypted at rest. Every item is
stored three times, sealed with **AES-256-CBC**, **DES-CBC** and
**RC4-drop3072**, each copy authenticated with HMAC-SHA256. Only the
logged-in employee can retrieve their own data, and a copy that fails its
integrity check is never returned.

The report is in [docs/REPORT.pdf](docs/REPORT.pdf)
(source: [docs/report.html](docs/report.html)).

## Run it

```bash
pip install -r requirements.txt
python scripts/seed_demo.py   # optional: demo employee emp-0001
python run.py                 # http://127.0.0.1:5000
```

The demo password is `onboarding-2026`. The seed script needs `ffmpeg` to
generate the demo interview video; without it, the video is skipped.
Runtime data (SQLite database and encrypted files) goes to `instance/`,
which is not committed. Delete that folder to start over.

## Tests

```bash
python -m pytest -q
```

`pyproject.toml` puts `src/` on the import path. The crypto tests
(`test_ciphers.py`, `test_envelope.py`, `test_keys.py`) cover round trips,
a fresh IV or nonce per message, tamper and context-swap detection and key
wrapping. The app tests (`test_auth.py`, `test_personal_data.py`,
`test_documents.py`, `test_account.py`) cover no plaintext or filenames at
rest, bit-exact retrieval from each copy, refusal of a tampered copy,
cross-user access, CSRF, cookie contents, password change and erasure.

## Benchmark

```bash
taskset -c 2 python benchmark/run_benchmark.py   # ~2 min; --quick to try
```

Writes `benchmark/results/results.json`, `ciphers.csv` and `download.csv`.
The committed results are the ones used in the report.

## Coding rules

Every source file starts with a `PROJECT, 2026` header. Functions are at
most 20 lines (docstring included) with at most 4 parameters, files hold
at most 10 functions, lines are at most 80 columns, explanations live in
docstrings rather than comments inside functions, and there are no nested
functions or globals.

## Layout

```text
run.py                    start the development server
pyproject.toml            project metadata and pytest configuration
src/hrvault/
  __init__.py             application factory
  config.py, db.py        settings and SQLite schema
  crypto/ciphers.py       AES-CBC, DES-CBC and RC4-drop3072 primitives
  crypto/envelope.py      encrypt-then-MAC envelope (HMAC-SHA256)
  crypto/keys.py          PBKDF2 login secrets and vault-key wrapping
  crypto/vault_keys.py    per-cipher subkeys derived from the vault key
  catalog.py              stored fields and document types, classified
                          under UU PDP and GDPR
  owner.py                the logged-in user a storage call acts on
  personal.py             personal-data fields under the three ciphers
  documents.py            store, retrieve, verify and delete documents
  accounts.py             register, login, password change
  keystore.py             in-memory store of unwrapped keys
  web/                    Flask views: hooks, auth, personal, documents,
                          account
  templates/              Jinja pages
scripts/                  demo data generator and seed script
benchmark/                benchmark modules and committed results
tests/                    pytest suite
docs/                     report (HTML source and PDF)
```

To rebuild the PDF after editing the report:

```bash
google-chrome --headless=new --no-pdf-header-footer \
  --print-to-pdf=docs/REPORT.pdf "file://$PWD/docs/report.html"
```
