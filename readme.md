# RSA Implementation in Python

Ce projet implémente une version simplifiée de l’algorithme **RSA** permettant :  
- la génération de clés,  
- le chiffrement d’un message,  
- le déchiffrement d’un message.  

Le code est écrit en **Python** et utilise la bibliothèque **pycryptodome** pour les opérations cryptographiques.

---

## 📌 Prérequis

- Python **3.6+**
- Environnement virtuel Python (inclus dans `rsa_env/`)

---

## ⚙️ Installation

### 1. Activer l’environnement virtuel
```bash
source rsa_env/bin/activate
2. Installer les dépendances
pip install -r requirements.txt


Dépendance principale :

pycryptodome

🚀 Test rapide

Pour exécuter une démonstration complète (génération de clés, chiffrement et déchiffrement) :

python rsa_core.py

🧩 Utilisation dans votre code
from rsa_core import generer_cles, chiffrer_message, dechiffrer_message

# Générer les clés
public_key, private_key = generer_cles()

# Chiffrer un message
message_clair = "Votre message secret"
message_chiffre = chiffrer_message(message_clair, public_key)

# Déchiffrer le message
message_dechiffre = dechiffrer_message(message_chiffre, private_key)
print(message_dechiffre)  # → "Votre message secret"

🔑 Fonctions principales
Fonction	Description
generer_cles(size=1024)	Génère une paire de clés publique et privée.
chiffrer_message(message_clair, public_key)	Chiffre un message en utilisant la clé publique.
dechiffrer_message(message_chiffre_b64, private_key)	Déchiffre un message en utilisant la clé privée.
🗂️ Structure du projet
.
├── rsa_core.py          # Code principal de l'implémentation RSA
├── requirements.txt     # Liste des dépendances Python
└── rsa_env/             # Environnement virtuel Python

📝 Notes

La taille de clé par défaut est 1024 bits (modifiable dans rsa_core.py via KEY_SIZE).

Ce projet est destiné à des fins éducatives.
Pour un usage en production, utilisez des bibliothèques cryptographiques robustes telles que :

cryptography

pycryptodome
