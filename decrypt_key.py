# decrypt_key.py
import sys
import win32crypt
import binascii

def main():
    if len(sys.argv) != 2:
        print("Usage: decrypt_key.exe <base64_key>")
        sys.exit(1)

    base64_key = sys.argv[1]
    encrypted_key = binascii.a2b_base64(base64_key)

    try:
        decrypted = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        print(binascii.b2a_base64(decrypted).decode().strip())
    except Exception as e:
        print(f"Error decrypting key: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
