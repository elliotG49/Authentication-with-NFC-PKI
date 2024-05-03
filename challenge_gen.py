import time
import secrets
import random

def challenge_gen(UID):
    try:
        t = time.localtime()
        timestamp = time.strftime("%D-%H%M%S", t)  # Date and current time in Hours/Minutes/Seconds
        nonce = secrets.randbelow(9999999999) + 1
        issuer = '001'
        

        challenge = f"{issuer}-{UID}-{nonce}-{timestamp}"  # All seeds are separated by a hyphen
        return challenge
    except Exception as error:
        return "Cryptographic challenge was unable to be created"  # Specific error message for requirements

# Open the UID file to read the UID
with open('/home/elliot/Desktop/NFC/data_store/uid.txt', 'r') as uid_file:
    uid = uid_file.read().strip()  # Reads the UID and strips the newline character

# Generate the challenge
challenge = challenge_gen(uid)
print(challenge)  # Print the challenge to the console

#Write the challenge to a new file
log_path = f"/home/elliot/Desktop/NFC/data_store/{uid}-challenge.txt"
with open(log_path, 'w') as log_file:
    log_file.write(challenge)  # Writes the challenge to the specified file