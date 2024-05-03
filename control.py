import subprocess
import time

def id():
    print("Place the device on the reader")
    time.sleep(1)
    write_ud_process = subprocess.run(["/home/elliot/Desktop/nfc/writing_data/write_uid"], capture_output=True)
    if write_ud_process.returncode != 0:
        print(write_ud_process.stderr.decode())
        return
    print("ID has been sent via NFC")

    main_toggle = int(input("Please press '1' when device is held over reader: "))
    if main_toggle == 1:
        main()
    else:
        print("Invalid Input")
        print("Transaction Cancelled")

def main():
    read_challenge_process = subprocess.run(["/home/elliot /Desktop/nfc/reading_data/read_challenge"], capture_output=True)
    if read_challenge_process.returncode == 0:
        print(read_challenge_process.stdout)
        return
    
    print("Challenge is Read")
    subprocess.run(["python3", "/home/elliot/Desktop/nfc/reading_data/format_challenge.py"])
    signing_challenge_process = subprocess.run(["python3", "/home/elliot/Desktop/nfc/signing_data/key-signing.py"], capture_output=True, text=True)
    if signing_challenge_process != "successfully":
        print(signing_challenge_process.stdout)

        write_signature_process = subprocess.run(["/home/elliot/Desktop/nfc/writing_data/write_signature_process"], capture_output=True)
        if write_signature_process.returncode !=0:
            print(write_signature_process.stdout)
        
        print("Signature Wrote")

id()