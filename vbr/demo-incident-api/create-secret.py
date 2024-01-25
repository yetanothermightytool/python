import base64
import getpass

def encode_password(password):
    return base64.b64encode(password.encode()).decode()

def save_password(encoded_password):
    with open("secret.txt", "w") as file:
        file.write(encoded_password)

def get_password_from_user():
    return getpass.getpass("Enter your password: ")


password                = get_password_from_user()
encoded_password        = encode_password(password)

save_password(encoded_password)
print("Encoded Password created:", encoded_password)
