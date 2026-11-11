<!--
  PROJECT, 2026
  info_security
  File description:
  Index of the three Information Security assignments.
-->

# Information Security assignments

Each assignment lives in its own folder and is a complete, runnable copy
of the Onboarding Vault web application. Every assignment starts from a
copy of the previous one and adds its new feature on top.

| Folder | Topic |
| --- | --- |
| [assignment1/](assignment1/) | Data encrypted at rest with AES, DES and RC4 |
| [assignment2/](assignment2/) | Sharing data between users with RSA key pairs |
| [assignment3/](assignment3/) | Digital signatures embedded in uploaded PDFs |

Each folder has its own README, requirements, tests and `instance/` data
folder. Run every command from inside the folder of the assignment:

```bash
cd assignment3
pip install -r requirements.txt
python -m pytest -q
python run.py                 # http://127.0.0.1:5000
```
