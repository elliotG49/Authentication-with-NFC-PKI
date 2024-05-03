#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <nfc/nfc.h>
#include <freefare.h>

int main(void) {
    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    nfc_context *context;
    int write_success = 1; // Assume success unless a write fails

    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "Unable to init libnfc (malloc).\n");
        exit(EXIT_FAILURE);
    }

    device = nfc_open(context, NULL);
    if (device == NULL) {
        fprintf(stderr, "Unable to open NFC device.\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    tags = freefare_get_tags(device);
    if (!tags) {
        fprintf(stderr, "Error listing MIFARE Classic tags.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    char data[64];
    FILE *pyProcess = popen("/usr/bin/python3 /home/elliot/Desktop/NFC/challenge/challenge_gen.py", "r");
    if (pyProcess == NULL) {
        fprintf(stderr, "Failed to run Python script.\n");
        exit(EXIT_FAILURE);
    }

    if (fgets(data, sizeof(data), pyProcess) == NULL) {
        fprintf(stderr, "Failed to read output from Python script.\n");
        pclose(pyProcess);
        exit(EXIT_FAILURE);
    }
    pclose(pyProcess);
    data[strlen(data) - 1] = '\0'; // Ensure null-termination and remove newline if present

    for (int i = 0; tags[i] != NULL; i++) {
        if (freefare_get_tag_type(tags[i]) == MIFARE_CLASSIC_1K) {
            MifareClassicKey default_key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

            if (mifare_classic_connect(tags[i]) < 0) {
                fprintf(stderr, "Can't connect to MIFARE Classic tag.\n");
                continue;
            }

            for (int block = 4; block <= 6; block++) {
                if (mifare_classic_authenticate(tags[i], block, default_key, MFC_KEY_A) < 0) {
                    fprintf(stderr, "Authentication failed for block %d.\n", block);
                    continue;
                }

                MifareClassicBlock block_data;
                memcpy(block_data, data + (block - 4) * 16, 16); // Copy a chunk of 16 bytes into block_data

                if (mifare_classic_write(tags[i], block, block_data) < 0) {
                    fprintf(stderr, "Write failed for block %d.\n", block);
                    write_success = 0; // Mark as failure
                } else {
                    printf("Successfully wrote to block %d.\n", block);
                }
            }

            mifare_classic_disconnect(tags[i]);
        }
        freefare_free_tag(tags[i]);
    }

    nfc_close(device);
    nfc_exit(context);
    return write_success; // Return 1 if all writes were successful, 0 otherwise
}
