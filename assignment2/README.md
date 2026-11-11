<!--
  PROJECT, 2026
  info_security
  File description:
  Assignment 2 overview: sharing data with RSA key pairs.
-->

# Onboarding Vault: Assignment 2

Information Security, Assignment 2. This folder starts from a copy of
[Assignment 1](../assignment1/) and adds **sharing between users with
public-key cryptography**: an employee (for example an HR officer) asks
for another employee's onboarding file, the owner approves or declines,
and only the requester can decrypt what was shared.

> The original brief of this assignment was lost. This folder implements
> the usual second step of the course: give every user an RSA key pair
> and use it to share encrypted data with another user, without ever
> giving away the owner's own keys.

## How it works

1. **Key pair.** On first login every user gets an RSA key pair
   (2048-bit, e = 65537). The public key is stored in clear. The private
   key is stored as PKCS#8, sealed with the user's own AES subkey
   (AES-256-CBC + HMAC-SHA256, bound to `user:<id>|rsa-private-key`), so
   it can only be opened while that user is logged in.
2. **Request.** The requester enters the owner's employee number on the
   Sharing page. The request is *pending*.
3. **Approve.** The owner sees the requester's key fingerprint and can
   check it with them before approving. On approval the server draws a
   fresh random 32-byte share key, re-seals a snapshot of the owner's
   personal data and documents under it (AES envelope bound to the
   request id), and stores the share key **encrypted with the
   requester's public key** (RSA-OAEP, SHA-256).
4. **Read.** The requester's private key unwraps the share key, which
   opens the snapshot. Every item is checked by its HMAC first; a
   tampered copy is never released.
5. **Decline or revoke.** Declining gives nothing. Revoking an approved
   share deletes the snapshot, so the wrapped key no longer opens
   anything. Erasing an account deletes every share it gave or received.

The owner's vault key never leaves the owner's account, and the server
never stores a share key in clear.

| Primitive | Use |
| --- | --- |
| RSA-2048 key generation | one key pair per user |
| RSA-OAEP (SHA-256) | transports the share key to the requester |
| AES-256-CBC + HMAC-SHA256 | seals the private key and the shared copy |

Libraries: `pycryptodome` for key generation, hashing and encryption.

## Limits

* A share is a **snapshot** taken at approval time: later edits by the
  owner are not visible until they share again.
* The server performs the re-encryption, so a compromised running server
  could read data of logged-in users (as in Assignment 1).
* Fingerprints must be compared out of band to rule out a fake account.

## Run it

```bash
pip install -r requirements.txt
python demo/seed.py           # optional: emp-0001 and hr-0001
python run.py                 # http://127.0.0.1:5000
```

Both demo users have the password `onboarding-2026`. Log in as
`emp-0001`, approve `hr-0001`'s request on **Sharing**, then log in as
`hr-0001` and open the shared file.

## Tests

```bash
python -m pytest -q
```

On top of the Assignment 1 tests: `test_rsa_keys.py` (sealed private
key, OAEP round trip, wrong key refused), `test_keypairs.py` (key pair
created once at first login, private key not stored in clear),
`test_sharing.py` (approve, read bit-exact, reject, revoke, third-user
isolation, encryption at rest, tampering, erasure) and
`test_sharing_requests.py` (self, unknown and duplicate requests).

## Layout (new files)

```text
src/hrvault/
  crypto/rsa_keys.py      RSA generation, sealed private key, OAEP
  keypairs.py             each user's key pair in the database
  sharing.py              access requests: create, list, record decision
  share_snapshot.py       approve (re-seal + wrap key), decline, revoke
  shared_view.py          requester side: unwrap the key, read the copy
  web/sharing.py          sharing routes
  templates/sharing.html, templates/shared_file.html
```
