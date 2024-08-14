import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

# AES Encryption
def aes_encrypt(text, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    return b64encode(encrypted_text).decode()

def aes_decrypt(encrypted_text, key):
    encrypted_text = b64decode(encrypted_text)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    return decrypted_text.decode()

# DES Encryption
def pad(data):
    """Pad data to be a multiple of DES block size (8 bytes)."""
    pad_length = 8 - len(data) % 8
    return data + bytes([pad_length] * pad_length)

def unpad(data):
    """Remove padding from data."""
    pad_length = data[-1]
    return data[:-pad_length]

def des_encrypt(text, key):
    """Encrypt text using DES."""
    cipher = DES.new(key, DES.MODE_CBC)  # Use CBC mode
    padded_text = pad(text.encode())
    ciphertext = cipher.encrypt(padded_text)
    return b64encode(cipher.iv + ciphertext).decode()

def des_decrypt(encrypted_text, key):
    """Decrypt text using DES."""
    encrypted_text = b64decode(encrypted_text)
    iv = encrypted_text[:8]
    ciphertext = encrypted_text[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = cipher.decrypt(ciphertext)
    return unpad(padded_text).decode()

# RSA Encryption
def rsa_generate_keypair():
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    """Encrypt text using RSA."""
    encrypted_text = public_key.encrypt(
        text.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return b64encode(encrypted_text).decode()

def rsa_decrypt(encrypted_text, private_key):
    """Decrypt text using RSA."""
    encrypted_text = b64decode(encrypted_text)
    decrypted_text = private_key.decrypt(
        encrypted_text,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_text.decode()

# Main function for user interaction
def main():
    print("Choose encryption algorithm:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")

    choice = input("Enter choice (1/2/3): ").strip()
    text = input("Enter text to encrypt: ").strip()

    if choice == '1':
        key = os.urandom(16)  # AES requires a 16-byte key
        encrypted = aes_encrypt(text, key)
        decrypted = aes_decrypt(encrypted, key)
        print(f"AES Encrypted: {encrypted}")
        print(f"AES Decrypted: {decrypted}")

    elif choice == '2':
        key = get_random_bytes(8)  # DES requires an 8-byte key
        encrypted = des_encrypt(text, key)
        decrypted = des_decrypt(encrypted, key)
        print(f"DES Encrypted: {encrypted}")
        print(f"DES Decrypted: {decrypted}")

    elif choice == '3':
        private_key, public_key = rsa_generate_keypair()
        encrypted = rsa_encrypt(text, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)
        print(f"RSA Encrypted: {encrypted}")
        print(f"RSA Decrypted: {decrypted}")

    else:
        print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
