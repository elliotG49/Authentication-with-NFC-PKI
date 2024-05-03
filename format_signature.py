unf_signature_path = '/home/elliot/Desktop/NFC/data_store/extracted_signature.txt'
f_signature_path = '/home/elliot/Desktop/NFC/data_store/signature.txt'

with open(unf_signature_path, 'r') as file:
    unf_signature = file.read()
    f_signature = unf_signature.replace('\n', '').replace(' ', '').replace('.', '')

with open(f_signature_path, 'w') as file2:
    file2.write(f_signature)
