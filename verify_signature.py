"""
Скрипт перевіряє автентичність зображення, підписаного за допомогою RSA.
Підпис попередньо вбудований у зображення методом стеганографії через LSB (найменш значущі біти).
"""

import hashlib
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def extract_signature(image_path, sig_length=512):
    """
    Витягує цифровий підпис із зображення, в якому він був вбудований в найменш значущі біти.
    """
    img = Image.open(image_path)
    pixels = list(img.getdata())
    bits = ""
    needed_bits = sig_length * 8
    bit_count = 0

    for pixel in pixels:
        for color in pixel[:3]:
            bits += str(color & 1)
            bit_count += 1
            if bit_count >= needed_bits:
                break
        if bit_count >= needed_bits:
            break

    bytes_out = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
    return bytes(bytes_out)

def load_public_key(path):
    """
    Завантажує публічний RSA-ключ у форматі PEM.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def hash_image(image_path):
    """
    Обчислює SHA-256 хеш вхідного зображення.
    """
    with open(image_path, 'rb') as file:
        data = file.read()
    return hashlib.sha256(data).digest()

def verify_signature(image_path, key, sign):
    """
    Перевіряє цифровий підпис, порівнюючи підпис хешу зображення
    з тим, що був витягнутий зі зображення.
    """
    hash_photo = hash_image(image_path)
    try:
        key.verify(
            sign,
            hash_photo,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Підпис вірний!")
    except InvalidSignature:
        print("Підпис недійсний!")

if __name__ == "__main__":
    SIGNED_IMAGE_PATH = "signed_image.png"
    ORIGINAL_IMAGE_PATH = "original_image.png"
    signature = extract_signature(SIGNED_IMAGE_PATH)
    public_key = load_public_key("public_key.pem")
    verify_signature(ORIGINAL_IMAGE_PATH, public_key, signature)
