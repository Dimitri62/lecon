# Question 0 
# Algorithmes symétriques : AES 256 avec XTS : Type : Symétrique Statut : Sûr ; AES 128 avec ECB : Type : Symétrique Statut : Non recommandé
# 3DES (Triple DES) : Type : Symétrique Statut : Obsolète ; 
# Algorithmes asymétriques : RSA avec OAEP : Type : Asymétrique Statut : Sûr
# RSA avec PKCS1 : Type : Asymétrique Statut : Obsolète
# Algorithmes de hachage : SHA-2 (SHA-256, SHA-512, etc.) : Type : Hachage Statut : Sûr ; SHA-1 : Type : Hachage Statut : Obsolète MD5 : Type : Hachage Statut : Obsolète

# Récapitulatif des algorithmes à éviter :

    # AES avec ECB : Faible à cause du mode ECB, même si AES est sécurisé.
    # 3DES : Obsolète et vulnérable.
    # RSA avec PKCS1 : Moins sécurisé que RSA avec OAEP.
    # SHA-1 : Dépassé, vulnérable aux attaques de collision.
    # MD5 : Hautement vulnérable, obsolète.


# Question 1 a 4
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets

# Fonction pour chiffrer un message avec AES256
def chiffre_message(cle, iv, message):
    padder = padding.PKCS7(128).padder()  # Ajoute du padding pour correspondre à la taille du bloc
    message = message.encode()  # Encode le message en bytes
    message_padded = padder.update(message) + padder.finalize()  # Applique le padding
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())  # Crée l'objet de chiffrement AES avec la clé et le IV
    encryptor = cipher.encryptor()  # Initialise l'encryptor
    ct = encryptor.update(message_padded) + encryptor.finalize()  # Chiffre le message
    return ct

# Fonction pour déchiffrer un message
def dechiffre_message(cle, iv, ct):
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())  # Crée l'objet de déchiffrement AES avec la clé et le IV
    decryptor = cipher.decryptor()  # Initialise le décryptor
    message_padded = decryptor.update(ct) + decryptor.finalize()  # Déchiffre le message
    unpadder = padding.PKCS7(128).unpadder()  # Enlève le padding
    message = unpadder.update(message_padded) + unpadder.finalize()  # Applique le retrait du padding
    return message.decode()  # Retourne le message original

# Génération d'une clé AES256 (32 bytes)
keygen = secrets.token_bytes(32)  # 32 bytes = 256 bits
# Génération d'un vecteur d'initialisation (IV) (16 bytes)
ivgen = secrets.token_bytes(16)  # 16 bytes = 128 bits
c = chiffre_message(keygen,ivgen,"test")
dechiffre_message(keygen,ivgen,c)

clé = keygen
iv = ivgen

print(clé)
print(iv)
print(chiffre_message(clé,iv,"salut mec"))

cclé = b'D\xb1\xe2\xf0\x8d\x86\xc8\xe6\xc1\x02ZO\xe0Y\x04\xe5XE)\xc4\x80&\x0c\xce\x85\xa1\x84\x0b\x82\xe2.\xa3'
iiv = b'\x84|\xffy\x80ngn\xa8{\xce\x80\xac1\x99\xff'
mess = b'\x80>_\x07\xe0r\xd5\xbc8\x1a\xdc\xfb\x15\xb0\x82\xbf'

print(dechiffre_message(cclé,iiv,mess))

# Question 5 : Comment pourrait-on s'assurer de l'intégrité du message et de l'authenticité du destinataire ? Signature numérique (authenticité) : Elle permet de vérifier 
# que le message provient bien du destinataire prétendu et n'a pas été modifié en cours de route.
# Code d'authentification de message (MAC) ou HMAC (intégrité) : Cela permet de vérifier que le message n'a pas été altéré.

# Question 7 : le message suivant a été intercepté: "prggr grpuavdhr f'nccryyr yr puvsserzrag qr prnfre, vy a'rfg cyhf hgvyvft nhwbheq'uhv, pne crh ftphevft", il semble vulnérable à 
# une attaque en fréquences ou une attaque par force brute. Déchiffrez-le ! CETTE TECHNIQUE S'APPELLE LECHIFFREMENT DE CEASER IL N'EST PLUS UTILISE AUJOURDHUI CAR PEU SECURISE

# Question 8 : Nous suspectons qu'un adversaire a implémenté une backdoor dans notre logiciel de messagerie sécurisé, pourtant nous utilisons AES-CBC, voici les logs  :
# L'IV semble être réutilisé dans plusieurs échanges (par exemple, '\xde@=\x1ed\xc0Qe\x0fK=\x1c\xb3$\xd9\xcb' apparaît plusieurs fois). Cette réutilisation pourrait 
# permettre à un attaquant d'inférer certaines parties des messages échangés, même s'ils sont chiffrés.
# Solution : S'assurer que chaque message utilise un IV différent, généré de manière aléatoire.



#Question 9 : Nous avons intercepté le message suivant: b'\xd72U\xc03.\xda\x99Q\xb5\x020\xc4\xb8\x16\xc6\xfa-\xb9U+\xda\\\x126L\xf3~\xbd8\x12q\x02?\x80\xeaVI\xa9\xe1'.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import itertools

# Fonction de déchiffrement Triple DES
def des_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_data = unpadder.update(pt) + unpadder.finalize()
    return unpadded_data

#Message chiffré
ciphertext = b'\xd72U\xc03.\xda\x99Q\xb5\x020\xc4\xb8\x16\xc6\xfa-\xb9U+\xda\\\x126L\xf3~\xbd8\x12q\x02?\x80\xeaVI\xa9\xe1'

#Clé partielle
key_part = b'12345678bien'

#Caractères possible ASCII seulement les lettres minuscules
possible_chars = map(chr, range(97, 123))

#Test des combinaisons possibles pour compléter la clé
for chars in itertools.product(possible_chars, repeat=4):
    key = key_part + ''.join(chars).encode()
    try:
        plaintext = des_decrypt(key, ciphertext)
        print("Clé trouvée :", key)
        print("Message déchiffré :", plaintext.decode('utf-8'))
        break
    except Exception as e:
        continue





    