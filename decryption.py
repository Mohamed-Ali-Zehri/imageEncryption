from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np

def decrypt_image(encrypted_package, private_key):
    (encrypted_key_package, iv, encrypted_image, shape, mode) = encrypted_package

    symmetric_key = decrypt_key(private_key, encrypted_key_package)

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_image = decryptor.update(encrypted_image) + decryptor.finalize()

    img_array = np.frombuffer(decrypted_image, dtype=np.uint8).reshape(shape)
    return Image.fromarray(img_array, mode=mode)

def extract_hidden_data(filename):
    # Load the image with hidden data
    img = np.array(Image.open(filename))

    # Extract the least significant bits
    bits = img.reshape(-1) & 1

    # Convert bits to bytes
    data = np.packbits(bits)

    # Extract the components
    i = 0
    key_length = int.from_bytes(data[i:i+4], byteorder='big')
    i += 4
    ephemeral_public_key = data[i:i+key_length].tobytes()
    i += key_length
    key_iv = data[i:i+16].tobytes()
    i += 16
    encrypted_key = data[i:i+32].tobytes()
    i += 32
    encrypted_key_package = (ephemeral_public_key, key_iv, encrypted_key)

    iv = data[i:i+16].tobytes()
    i += 16

    image_length = int.from_bytes(data[i:i+4], byteorder='big')
    i += 4
    encrypted_image = data[i:i+image_length].tobytes()
    i += image_length

    shape_length = int.from_bytes(data[i:i+4], byteorder='big')
    i += 4
    shape = tuple(int.from_bytes(data[i+j*4:i+(j+1)*4], byteorder='big') for j in range(shape_length))
    i += shape_length * 4

    mode = data[i:].tobytes().decode().rstrip('\x00')

    return (encrypted_key_package, iv, encrypted_image, shape, mode)

def load_and_decrypt_hidden_image(filename, private_key):
    encrypted_package = extract_hidden_data(filename)
    return decrypt_image(encrypted_package, private_key)