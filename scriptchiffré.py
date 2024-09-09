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