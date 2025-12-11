from Crypto.Util import number
import random
import base64

# --- CONFIGURATION ---
# 1. Définir la taille de la clé (C'est ce qui manquait)
KEY_SIZE = 1024
# 2. Calculer la taille en octets pour le découpage
KEY_SIZE_BYTES = KEY_SIZE // 8

# --- FONCTIONS MATHÉMATIQUES DE BASE ---

def pgcd(a, b):
    """Calcule le plus grand commun diviseur (PGCD)."""
    while b:
        a, b = b, a % b
    return a

def euclide_etendu(e, m):
    """
    Calcule l'inverse modulaire via l'algorithme d'Euclide étendu.
    Retourne (x, y, pgcd) tel que a*x + b*y = pgcd
    """
    if m == 0:
        return 1, 0, e
    
    x1, y1, pgcd_val = euclide_etendu(m, e % m)
    x = y1
    y = x1 - (e // m) * y1
    return x, y, pgcd_val

def inverse_modulaire(e, m):
    """Calcule l'inverse modulaire d."""
    x, y, pgcd_val = euclide_etendu(e, m)
    if pgcd_val != 1:
        raise ValueError("L'inverse modulaire n'existe pas (e et m ne sont pas premiers entre eux).")
    return x % m

def exponentiation_rapide(base, exp, mod):
    """Calcule (base^exp) % mod efficacement."""
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        
        # CORRECTION IMPORTANTE ICI : Division par 2, pas par 1 !
        exp = exp // 2  
        base = (base * base) % mod
    return result

# --- GÉNÉRATION DE CLÉS ---

def generer_e_aleatoire(phi_n, min_val=65537):
    """Génère un e aléatoire premier avec phi_n."""
    while True:
        e = random.randint(min_val, phi_n - 1)
        if e % 2 == 0: # e doit être impair
            continue
        if pgcd(e, phi_n) == 1:
            return e

def generer_cles(size=KEY_SIZE):
    """Génère les clés publique et privée RSA."""
    # 1. Générer p et q (nombres premiers forts)
    p = number.getPrime(size // 2)
    q = number.getPrime(size // 2)
    
    # 2. Calculer n
    n = p * q
    
    # 3. Calculer phi(n)
    phi_n = (p - 1) * (q - 1)
    
    # 4. Choisir e (Standard F4 ou aléatoire selon l'énoncé)
    # Pour le TP, on utilise souvent 65537, mais voici la version aléatoire :
    e = generer_e_aleatoire(phi_n)
        
    # 5. Calculer d
    d = inverse_modulaire(e, phi_n)
    
    return (n, e), (n, d)

# --- UTILITAIRES DE CONVERSION ---

def bytes_to_int(data):
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(data, size):
    return data.to_bytes(size, byteorder='big')

# --- CHIFFREMENT / DÉCHIFFREMENT ---

def chiffrer_message(message_clair, public_key):
    n, e = public_key
    # On garde une marge pour le padding (éviter que m > n)
    bloc_size = KEY_SIZE_BYTES - 1
    
    message_bytes = message_clair.encode('utf-8')
    chiffres = []

    for i in range(0, len(message_bytes), bloc_size):
        bloc = message_bytes[i:i + bloc_size]
        m_int = bytes_to_int(bloc)
        c_int = exponentiation_rapide(m_int, e, n)
        chiffres.append(int_to_bytes(c_int, KEY_SIZE_BYTES))

    resultat_chiffre = b''.join(chiffres)
    return base64.b64encode(resultat_chiffre).decode('utf-8')

def dechiffrer_message(message_chiffre_b64, private_key):
    n, d = private_key
    message_chiffre_bytes = base64.b64decode(message_chiffre_b64)
    
    bloc_size = KEY_SIZE_BYTES
    message_clair_bytes = []
    
    for i in range(0, len(message_chiffre_bytes), bloc_size):
        bloc_chiffre = message_chiffre_bytes[i:i + bloc_size]
        c_int = bytes_to_int(bloc_chiffre)
        m_int = exponentiation_rapide(c_int, d, n)
        
        # Retirer les octets nuls ajoutés lors de la conversion inverse
        try:
            # On essaie de convertir avec la taille max possible
            m_bytes = m_int.to_bytes(bloc_size, byteorder='big')
            # On enlève les zéros à gauche (padding du int_to_bytes)
            m_bytes = m_bytes.lstrip(b'\x00')
            message_clair_bytes.append(m_bytes)
        except OverflowError:
            print("Erreur de décodage d'un bloc")

    return b''.join(message_clair_bytes).decode('utf-8')

# --- TEST PRINCIPAL ---

if __name__ == "__main__":
    print(f"### Génération des Clés RSA ({KEY_SIZE} bits) ###")
    # Appel de la fonction generer_cles (maintenant définie plus haut)
    public_key, private_key = generer_cles(KEY_SIZE)
    
    n_val, e_val = public_key
    _, d_val = private_key
    
    print(f"\n[Clé Publique (n, e)]:")
    print(f"n (Module - début): {str(n_val)[:30]}...")
    print(f"e (Pub.): {e_val}")
    print(f"\n[Clé Privée (n, d)]:")
    print(f"d (Priv. - début): {str(d_val)[:30]}...")
    print("-" * 50)
    
    message = "Ceci est un message de test très secret pour le TP RSA."
    print(f"Message clair: '{message}'")

    # Chiffrement
    msg_chiffre = chiffrer_message(message, public_key)
    print(f"\nMessage chiffré (Base64) :\n{msg_chiffre[:50]}... (tronqué)")

    # Déchiffrement
    msg_dechiffre = dechiffrer_message(msg_chiffre, private_key)
    print(f"\nMessage déchiffré :\n'{msg_dechiffre}'")

    if message == msg_dechiffre:
        print("\n✅ SUCCÈS : Le chiffrement RSA fonctionne correctement.")
    else:
        print("\n❌ ÉCHEC : Le message déchiffré ne correspond pas.")