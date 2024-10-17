from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import hashlib

# Функция для проверки подписи
def verify_nft_signature(public_key, nft_hash, signature):
    try:
        # Проверка подписи с использованием публичного ключа
        public_key.verify(
            signature,
            nft_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Загрузка публичного ключа из файла
def load_public_key(filename):
    with open(filename, 'rb') as f:
        pem = f.read()
        public_key = serialization.load_pem_public_key(pem)
    return public_key, pem.decode()

# Предполагаем, что у нас уже есть публичный ключ и подпись от автора
public_key, nft_text = load_public_key('public_key.pem')

nft_hash = hashlib.sha256(nft_text.encode('utf-8')).hexdigest()
signature = bytes.fromhex('399c15c474e6f590780ee5a73f5b5fc4824514761304c39136e9567aa37edc36a405dc6c5dd48cebf255151a08c2b952a4a346a876e2d6292cd6c28e4f6aec8535e29e38984077677eab0a1f7cd0fed4bcab52fefd7d173d7120d0442c1a8d2475f8e79ac59cb5a1df5523e147bfc7c4834be23cc8b76e8ceeff8e67a4202dcfa28c4745a0ef5c8417ed32dc8f96b013410df25105f0a21a9e0d173e28b95834cdd0fcacd34e56ffc6d2572390957cd418d2b1d6f726e0aacc788391d05309f4003b36d2d3b11b990d2a3d724d85df6c71d066ed70bd8a6006d5eae8fcfde860121ee4a30cbd1447f0cd5b9abbc15f3a6de37fd46aed36b5a5bb5d1410903887')  # Здесь hex строка подписи

# Проверяем авторство
is_valid = verify_nft_signature(public_key, nft_hash, signature)
if is_valid:
    print("Подпись верна. Авторство подтверждено.")
else:
    print("Подпись неверна. Авторство не подтверждено.")