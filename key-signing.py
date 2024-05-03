from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


with open('/home/elliot/Desktop/nfc/signing_data/private-key.pem', 'rb') as key_file: # Opens the private key file
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open('/home/elliot/Desktop/nfc/data_store/challenge.txt', 'rb') as chall_file: # Opens the extracted challenge txt file
    challenge_to_sign = chall_file.read().strip()

signature = private_key.sign(challenge_to_sign) # signs the challenge

base64_signature = base64.b64encode(signature) # encodes the challenge in base64 format
base64_signature_str = base64_signature.decode('utf-8')

# Write the signature to a file
with open('/home/elliot/Desktop/nfc/data_store/b64_signature.bin', 'w') as signature_file:
    signature_file.write(base64_signature_str) # Writes the base64 encoded signature to a .bin file

print("Data signed successfully.")