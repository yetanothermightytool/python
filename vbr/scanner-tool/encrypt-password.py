#!/usr/bin/env python3
"""
One-time helper to encrypt the VBR password with a Fernet key.
Run once, then store the output in .env and the key file in a secure location.
"""
import getpass
from cryptography.fernet import Fernet

key = Fernet.generate_key()
key_file = "vbr.key"
with open(key_file, "wb") as f:
    f.write(key)

password = getpass.getpass("Enter VBR password: ")
encrypted = Fernet(key).encrypt(password.encode()).decode()

print(f"\nAdd to .env:")
print(f"VBR_PASSWORD={encrypted}")
print(f"VBR_KEY_FILE=/root/.vbr.key   # adjust path as needed")
print(f"\nKey saved to: {key_file}")
print("Move it to a secure location, e.g.:")
print(f"  sudo mv {key_file} /root/.vbr.key && sudo chmod 600 /root/.vbr.key")
