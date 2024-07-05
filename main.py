from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os


# Fungsi untuk melakukan enkripsi AES CBC
def encrypt_AES_CBC(key, iv, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext


# Fungsi untuk melakukan dekripsi AES CBC
def decrypt_AES_CBC(key, iv, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def text_to_bytes(text):
    # Mengonversi teks menjadi byte
    return text.encode()

def bytes_to_text(byte_sequence):
    # Mengonversi byte menjadi teks
    return byte_sequence.decode()

# Contoh penggunaan:
if __name__ == "__main__":
    text1 = "kunci123kurangya"
    byte_sequence = text_to_bytes(text1)
    key = byte_sequence
    # key = 03c6514dd78b0d3c9bfbc079f062dc4915f69af7fd0ae088566d36929e2ccb5b
    text2 = "jonathannahtanoj"
    byte_sequence2 = text_to_bytes(text2)
    iv = byte_sequence2  # Generate a random IV (Initialization Vector)

    plaintext = b"Jonathan Anandar Cahyadi"

    ciphertext = encrypt_AES_CBC(key, iv, plaintext)
    try:
        a = ciphertext.decode('latin-1')
        print(a)
    except UnicodeDecodeError:
        print("Unable to decode with Latin-1 encoding")

    decrypted_text = decrypt_AES_CBC(key, iv, ciphertext)

    print("Plaintext:", plaintext)
    print("iv:", iv)
    print("Key:", text1)
    print("Ciphertext:", a)
    print("Decrypted text:", decrypted_text.decode())
