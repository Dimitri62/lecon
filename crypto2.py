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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Fonction de déchiffrement
def dechiffre_message(cle, iv, ct):
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    message_padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(message_padded) + unpadder.finalize()
    return message.decode()

# Exemple de clé et d'IV (ils doivent être les mêmes que ceux utilisés pour chiffrer le message)
cle = b'\x00' * 32  # Remplacez cette clé par celle que vous avez utilisée
iv = b'\x00' * 16   # Remplacez cet IV par celui utilisé pour chiffrer

# Votre message chiffré
message_chiffre = b'>s\x06\x14\x0c\xa7\xa6\x88\xd5[+i\xcc/J\xf7'

# Déchiffrement du message
message_déchiffré = dechiffre_message(cle, iv, message_chiffre)
print("Message déchiffré :", message_déchiffré)

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





    