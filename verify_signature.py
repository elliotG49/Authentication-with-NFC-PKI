from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509 import load_pem_x509_certificate
import base64

def verify_signature():
    with open('/home/elliot/Desktop/NFC/data_store/signature.txt', 'r') as extracted_sig :
        encoded_signature = extracted_sig.read().strip()
        decoded_signature = base64.b64decode(encoded_signature)
        

    with open('/home/elliot/Desktop/NFC/data_store/uid.txt', 'r') as uid_file:
        uid = uid_file.read().strip()

    certificate_path = f'/home/elliot/Desktop/NFC/pki/signed-certificates/{uid}.pem'
    challenge_path = f'/home/elliot/Desktop/NFC/data_store/{uid}-challenge.txt'

    with open(challenge_path, 'rb') as challenge_file:
        challenge = challenge_file.read().strip()

    with open(certificate_path, 'rb') as certificate_file:
        pem_data = certificate_file.read()
        certificate = load_pem_x509_certificate(pem_data, default_backend())
        public_key = certificate.public_key()
        
    try: 
        public_key.verify(decoded_signature, challenge)
        print("Verified")
        return True
    except Exception as error:
        print("Signature Verification Failed") 
        
        
verify_signature()
