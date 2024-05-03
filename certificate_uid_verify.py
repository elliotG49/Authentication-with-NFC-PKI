import subprocess
import os

def check_uid_length(uid_file_path):
    try:
        with open(uid_file_path, 'r') as file:
            uid = file.read().strip()
            if len(uid) == 8:
                return True, uid
            else:
                return False, "Error: File does not contain an 8-digit UID."
    except FileNotFoundError:
        return False, "Error: UID file not found."

def check_if_id_in_ca(ca_file_path, search_uid):
    try:
        with open(ca_file_path, 'r') as file:
            content = file.read()
            if search_uid in content:
                return True, "UID Found in index database."
            else:
                return False, "UID not found in index database."
    except FileNotFoundError:
        return False, "Error: CA file not found."

def check_status_certificate(cert_path, root_cert_path, crl_path, uid):
    shell_command = [
        "openssl", "verify",
        "-CAfile", root_cert_path,
        "-CRLfile", crl_path,
        "-crl_check", cert_path
    ]

    result = subprocess.run(shell_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        return True, "Verification Successful for UID: " + uid
    else:
        return False, "Certificate Verification Failed: " + result.stderr

def main(uid_file_path, ca_file_path, root_cert_path, cert_path_base, crl_path):
    result, uid_or_error = check_uid_length(uid_file_path)
    if not result:
        print(uid_or_error)
        return False

    result, message = check_if_id_in_ca(ca_file_path, uid_or_error)
    if not result:
        print(message)
        return False

    cert_path = f"{cert_path_base}/{uid_or_error}.pem"
    result, message = check_status_certificate(cert_path, root_cert_path, crl_path, uid_or_error)
    if not result:
        print(message)
        return False

    return True

# Removed the __name__ check and directly call main function
uid_file_path = '/home/elliot/Desktop/NFC/data_store/uid.txt'
ca_file_path = '/home/elliot/Desktop/NFC/pki/database-index.txt'
root_cert_path = "/home/elliot/Desktop/NFC/pki/keys-root/root.crt"
cert_path_base = "/home/elliot/Desktop/NFC/pki/signed-certificates"
crl_path = "/home/elliot/Desktop/NFC/pki/revocation-List/crl.pem"

success = main(uid_file_path, ca_file_path, root_cert_path, cert_path_base, crl_path)
if success:
    print("True")  # For integration with the main script, printing success status.
else:
    print("False")
