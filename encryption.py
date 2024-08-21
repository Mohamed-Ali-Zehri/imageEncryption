import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np


def encrypt_image(image_path, public_key):
    img = Image.open(image_path)
    if img.mode == 'RGBA':
        img = img.convert('RGB')
    img_array = np.array(img)

    symmetric_key = os.urandom(32)
    encrypted_key_package = encrypt_key(public_key, symmetric_key)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_image = encryptor.update(img_array.tobytes()) + encryptor.finalize()

    return (encrypted_key_package, iv, encrypted_image, img_array.shape, img.mode)

def save_encrypted_image(encrypted_package, filename):
    (encrypted_key_package, iv, encrypted_image, shape, mode) = encrypted_package

    data = b''
    ephemeral_public_key, key_iv, encrypted_key = encrypted_key_package
    data += len(ephemeral_public_key).to_bytes(4, byteorder='big')
    data += ephemeral_public_key
    data += key_iv
    data += encrypted_key
    data += iv
    data += len(encrypted_image).to_bytes(4, byteorder='big')
    data += encrypted_image
    data += len(shape).to_bytes(4, byteorder='big')
    for dim in shape:
        data += dim.to_bytes(4, byteorder='big')
    data += mode.encode()

    # Create a black image to hide the data
    data_len = len(data)
    img_size = int(np.ceil(np.sqrt(data_len * 8 / 3)))
    black_img = np.zeros((img_size, img_size, 3), dtype=np.uint8)

    # Convert data to bit array
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))

    # Embed data in the least significant bits
    black_img.reshape(-1)[:len(bits)] |= bits

    # Save the image with hidden data
    Image.fromarray(black_img).save(filename)

def hide_encrypted_data(encrypted_package, output_filename):
    save_encrypted_image(encrypted_package, output_filename)
    print(f"Encrypted data hidden in {output_filename}")