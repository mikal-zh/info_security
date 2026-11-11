<!--
  PROJECT, 2026
  info_security
  File description:
  Assignment 3 overview: digital signatures embedded in PDFs.
-->

# Onboarding Vault: Assignment 3

Information Security, Assignment 3: **Digital Signature**. This folder
starts from a copy of [Assignment 2](../assignment2/) and adds:

* signing any uploaded PDF with the **owner's private key**, the
  signature being **embedded in the PDF** itself;
* verifying signatures in the web app, both for stored PDFs and for any
  PDF uploaded on the **Verify PDF** page;
* signatures that **third-party PDF readers verify** (Adobe Acrobat
  Reader, poppler / Okular / Evince, Foxit...);
* **generating a key pair** when the user has none, or importing the
  user's own RSA key.

## What is written by hand and what uses a library

The brief allows libraries only for key generation, hashing and
encryption. `pycryptodome` and `hashlib` are used for exactly that:

| Library call | Purpose |
| --- | --- |
| `RSA.generate`, `RSA.import_key` | generate or load the key pair |
| `hashlib.sha256`, `hashlib.sha1` | document digest, key identifier |
| `pow(m, d, n)` / `pow(s, e, n)` | the RSA operation itself |
| AES envelope from Assignment 1 | store the private key encrypted |

Everything else is implemented in this project, in `src/hrvault/`:

| Module | What it does |
| --- | --- |
| `crypto/pkcs1.py` | RSASSA-PKCS1-v1_5 padding, sign and verify |
| `crypto/der.py` | ASN.1 DER encoder and decoder |
| `pdfsign/certificate.py` | self-signed X.509 v3 certificate |
| `pdfsign/cms.py`, `cms_reader.py` | CMS SignedData (PKCS#7, detached) |
| `pdfsign/pdf_*.py` | PDF parser, xref tables and streams, writer |
| `pdfsign/signer.py` | signature field and incremental update |
| `pdfsign/verifier.py` | checks every signature of a PDF |

The test `test_hand_signature_matches_the_standard` checks that our
PKCS#1 signature is byte-for-byte the one `pycryptodome` would produce,
and OpenSSL and poppler validate our certificates and signatures.

## How a PDF is signed

1. The signed PDF is the original file, untouched, followed by an
   **incremental update** that adds a signature dictionary
   (`/Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached`), an
   invisible signature field on the first page, and a new catalog with
   `/AcroForm` and `/SigFlags 3`.
2. The signature dictionary reserves a `/Contents <000...>` placeholder.
   `/ByteRange [0 a b c]` lists everything **except** that placeholder.
3. The SHA-256 of those bytes goes into the CMS signed attributes
   (`contentType`, `signingTime`, `messageDigest`). These attributes
   are signed with the owner's private key: `S = EM^d mod n`, where EM
   is the PKCS#1 v1.5 encoding of their SHA-256.
4. The CMS structure (signed attributes, signature and the owner's
   certificate) is written in hex into the placeholder. The three
   encrypted copies of the document are replaced by the signed PDF.

Verification redoes it backwards: hash the `/ByteRange` bytes and
compare with `messageDigest` (the content is unchanged), check
`S^e mod n` against the signed attributes with the certificate's key
(that key really signed it), and match the key against the keys
registered in the vault (who signed it). Bytes appended after a
signature are reported, so a second signature keeps the first valid.

## Keys

The **Keys** page shows the key pair, or offers to:

* **Generate** a 2048-bit RSA key pair with a certificate
  `CN=<employee number>, O=Onboarding Vault`;
* **Import** the user's own RSA private key (PEM or DER, 2048 bits or
  more, optionally with a passphrase), for which a certificate is
  issued.

If a user signs a PDF (or asks for someone's file) without a key pair,
one is generated first. The private key is always stored sealed with
the user's own AES subkey, as in Assignment 2.

## Checking with a third-party reader

```bash
pdfsig signed.pdf      # poppler-utils
```

prints `Signature Validation: Signature is Valid.` and
`Total document signed`. The test suite runs this check automatically
when `pdfsig` is installed.

In **Adobe Acrobat Reader**, the signature panel shows the signature
and says the document has not been modified. Because the certificate
is self-signed, Adobe first says the signer's identity is unknown. To
get the green check, download the certificate from the Keys page
(`.cer`) and add it under *Preferences > Signatures > Identities &
Trusted Certificates > More > Trusted Certificates > Import*, ticking
"Use this certificate as a trusted root".

## Run it

```bash
pip install -r requirements.txt
python demo/seed.py           # optional: emp-0001 and hr-0001
python run.py                 # http://127.0.0.1:5000
```

Both demo users have the password `onboarding-2026`. Log in as
`emp-0001`, which has no key yet, and click the signature icon next to
`employment_contract.pdf`. A key pair is generated and the PDF is
signed. Download it and open it in a PDF reader, or check it on the
**Verify PDF** page.

## Tests

```bash
python -m pytest -q
```

On top of the Assignment 1 and 2 tests:

* `test_der_pkcs1.py`: DER encoding, PKCS#1 signature equal to the
  library's, tampering and wrong key detected;
* `test_certificate_cms.py`: certificate and CMS read back, and
  checked with OpenSSL;
* `test_pdf_reader.py`: PDF syntax, xref tables and xref streams with
  object streams, real LibreOffice and Ghostscript files, recovery of
  broken files, refusal of encrypted files;
* `test_pdf_signing.py`: sign each kind of PDF, detect a change, sign
  twice, check with poppler's `pdfsig`;
* `test_keypairs.py`, `test_key_import.py`: generation on request,
  sealed storage, certificate download, import and refusals;
* `test_signing_web.py`: signing through the web app, three copies
  rewritten, report, owner-only access, verifying an uploaded PDF.

## Limits

* The certificate is self-signed: readers confirm integrity and the
  key, but trusting the identity needs the certificate to be imported
  (or a company CA, out of scope).
* The signature is invisible (no stamp drawn on the page) and has no
  trusted timestamp (no long-term validation).
* Password-protected PDFs are refused. Stream filters other than
  FlateDecode are not needed to sign and are only decoded in
  cross-reference and object streams.
