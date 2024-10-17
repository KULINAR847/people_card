from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

# Генерация приватного и публичного ключей RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Функция для создания изображения NFT
def create_nft_image(text, output_path):
    img = Image.new('RGB', (600, 400), color=(73, 109, 137))
    d = ImageDraw.Draw(img)
    
    # Используем шрифт по умолчанию
    font = ImageFont.load_default()
    
    # Пишем текст в центре изображения
    text_width, text_height = d.textsize(text, font=font)
    position = ((600 - text_width) // 2, (400 - text_height) // 2)
    d.text(position, text, fill=(255, 255, 0), font=font)
    
    # Сохраняем изображение
    img.save(output_path)

# Создаем уникальный хеш для NFT
def create_nft_hash(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# Подписываем хеш приватным ключом
def sign_nft(private_key, nft_hash):
    signature = private_key.sign(
        nft_hash.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Сохранение публичного ключа в файле
def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

# Пример создания NFT сертификата


ppem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

nft_text = ppem.decode() #"NFT Certificate #1"
image_path = "nft_certificate.png"


# Создаем изображение
create_nft_image(nft_text, image_path)

# Генерируем хеш и подписываем его
nft_hash = create_nft_hash(nft_text)
signature = sign_nft(private_key, nft_hash)

# Сохраняем публичный ключ
save_public_key(public_key, 'public_key.pem')

# Выводим результат
print(f"NFT Hash: {nft_hash}")
print(f"Signature: {signature.hex()}")
print(f"NFT Image saved as {image_path}")