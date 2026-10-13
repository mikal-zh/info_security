# Information Security Assignment 1: Secure Cryptographic Vault

A production-grade, compliant web application for storing confidential personal data (aligned with **EU GDPR** & **Indonesian UU PDP No. 27/2022**) and encrypted file vaults (ID Cards, Documents, Videos) using **AES-256 (CBC)**, **DES (CBC)**, and **RC4 (Stream)**.

Includes a comprehensive **Multi-Cipher Benchmark & Analysis Laboratory** and an in-browser academic **Report Viewer**.

---

## 📁 Architecture & Structure du Projet

Le projet a été soigneusement structuré et rangé de manière modulaire :

```text
info_security/
├── app.py                      # Point d'entrée principal (Serveur Web Flask)
├── requirements.txt            # Liste des dépendances pip
├── README.md                   # Documentation et guide d'utilisation
├── REPORT.md                   # Rapport académique complet
├── .gitignore                  # Fichiers et dossiers ignorés par git
│
├── src/                        # Code source métier & logique cryptographique
│   ├── __init__.py
│   ├── crypto_manager.py       # Moteur de chiffrement AES-CBC, DES-CBC, RC4 & profiling
│   └── database.py             # Gestion SQLite, PBKDF2 et persistance des données
│
├── templates/                  # Templates HTML Jinja2 (Interface TailwindCSS & Chart.js)
│   ├── base.html               # Layout principal et barre de navigation responsive
│   ├── login.html              # Authentification utilisateur
│   ├── register.html           # Inscription sécurisée
│   ├── dashboard.html          # Vue d'ensemble, métriques et fichiers récents
│   ├── profile.html            # Données privées GDPR/UU PDP & inspecteur de ciphertext
│   ├── files.html              # Coffre-fort numérique (KTP, Documents, Vidéos)
│   ├── upload.html             # Chiffrement & téléversement multi-algorithmes
│   ├── benchmark.html          # Laboratoire d'analyse de performance et graphiques
│   └── report.html             # Visualiseur web du rapport académique
│
├── scripts/                    # Scripts utilitaires et d'évaluation
│   ├── seed_sample_data.py     # Initialisation avec données de test et mock KTP
│   └── benchmark_cli.py        # Benchmark automatisé en ligne de commande (export CSV)
│
├── tests/                      # Suite de tests automatisés (Unit & Intégration)
│   ├── __init__.py
│   └── test_app.py             # Tests d'authentification, chiffrement et API
│
├── data/                       # Stockage persistant isolé (Zéro texte clair)
│   ├── secure_vault.db         # Base de données SQLite chiffrée
│   └── uploads/                # Fichiers chiffrés sur le disque (.enc uniquement)
│
└── output/                     # Résultats et exports de benchmarks
    └── benchmark_results.csv   # Export des mesures statistiques
```

---

## 🚀 Guide de Démarrage Rapide

### 1. Installation des Dépendances
```bash
py -m pip install -r requirements.txt
```

### 2. Initialiser la Base et les Données de Test
Ce script crée un compte de démonstration, renseigne les données personnelles chiffrées conformes GDPR/UU PDP et génère des fichiers de test (fausse carte KTP PNG, document PDF, flux vidéo) chiffrés sous AES, DES et RC4 :
```bash
py scripts/seed_sample_data.py
```
*Identifiants de démonstration :*
- **Nom d'utilisateur :** `student_group`
- **Mot de passe :** `Password123!`

### 3. Lancer l'Application Web
```bash
py app.py
```
Accédez à l'application dans votre navigateur : **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### 4. Exécuter la Suite de Tests Automatisés
```bash
py tests/test_app.py
```

### 5. Exécuter le Benchmark en Ligne de Commande
```bash
py scripts/benchmark_cli.py --size 1024 --iterations 10
```
Les résultats sont automatiquement enregistrés dans `output/benchmark_results.csv`.

---

## 🔒 Principes Cryptographiques et Conformité

1. **Mode Non-ECB obligatoire :**
   - Utilisation du mode **CBC (Cipher Block Chaining)** avec remplissage **PKCS#7** pour AES et DES.
   - Vecteur d'initialisation (**IV**) aléatoire et unique généré via un générateur cryptographiquement sûr (`Crypto.Random.get_random_bytes`) pour chaque opération. Format : `[IV] + [Ciphertext]`.
   - **RC4 :** Chiffre à flux fonctionnant par XOR sur keystream sans padding.

2. **Authentification & Dérivation de Clés :**
   - Hachage des mots de passe par **PBKDF2-HMAC-SHA256** (100 000 itérations) avec sel aléatoire de 16 octets.
   - Dérivation des clés de chiffrement par utilisateur avec **PBKDF2-HMAC-SHA256**.

3. **Protection des Données Personnelles (GDPR / UU PDP No. 27/2022) :**
   - **Données spécifiques / sensibles :** NIK (Numéro d'identité national), coordonnées bancaires, données de santé.
   - **Données générales :** Nom, genre, religion, état civil, date/lieu de naissance, adresse, téléphone, email.
   - **Inspecteur de Ciphertext :** Permet de visualiser dans la base SQLite les chaînes Base64 chiffrées attestant de l'absence totale de fuite en clair.
