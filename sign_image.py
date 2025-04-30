"""
Скрипт створює цифровий підпис для зображення за допомогою алгоритму RSA
і вбудовує цей підпис у зображення методом стеганографії (LSB - найменш значущі біти).
"""

import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def hash_image(image_path):
    """
    Обчислює SHA-256 хеш для файлу зображення.
    """
    with open(image_path, 'rb') as file:
        data = file.read()
    return hashlib.sha256(data).digest()

def load_private_key(path):
    """
    Завантажує приватний RSA-ключ у форматі PEM.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )

def sign_hash(hash_bytes, key):
    """
    Підписує хеш за допомогою RSA-приватного ключа та схеми PSS.
    """
    return key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def embed_signature(image_path, signature, output_path):
    """
    Вбудовує цифровий підпис у зображення, використовуючи LSB-стеганографію.
    Кожен біт підпису вставляється у найменш значущі біти пікселів (R, G, B).
    """
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = ''.join(f'{byte:08b}' for byte in signature)
    bit_idx = 0
    max_bits = len(bits)

    new_pixels = []
    for pixel in pixels:
        red, green, blue = pixel
        if bit_idx < max_bits:
            red = (red & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < max_bits:
            green = (green & ~1) | int(bits[bit_idx])
            bit_idx += 1
        if bit_idx < max_bits:
            blue = (blue & ~1) | int(bits[bit_idx])
            bit_idx += 1
        new_pixels.append((red, green, blue))

    if bit_idx < max_bits:
        raise ValueError("Зображення замале для підпису!")

    img.putdata(new_pixels)
    img.save(output_path)
    print(f"Збережено підписане зображення як {output_path}")

if __name__ == "__main__":
    ORIGINAL_IMAGE_PATH = "original_image.png"
    SIGNED_IMAGE_PATH = "signed_image.png"
    private_key = load_private_key("private_key.pem")
    HASH_CODE = hash_image(ORIGINAL_IMAGE_PATH)
    sig = sign_hash(HASH_CODE, private_key)
    embed_signature(ORIGINAL_IMAGE_PATH, sig, SIGNED_IMAGE_PATH)
