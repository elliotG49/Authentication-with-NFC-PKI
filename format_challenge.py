unf_challenge_path = '/home/elliot/Desktop/nfc/data_store/extracted_data.txt'
f_challenge_path = '/home/elliot/Desktop/nfc/data_store/challenge.txt'

with open(unf_challenge_path, 'r') as file:
    unf_challenge = file.read()
    f_challenge = unf_challenge.replace('\n', '').replace(' ', '').replace('.', '')

with open(f_challenge_path, 'w') as file2:
    file2.write(f_challenge)