#include <stdlib.h>
#include <stdio.h>
#include <nfc/nfc.h>
#include <freefare.h>

int main(void) {
    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    nfc_context *context;
    FILE *fp;
    int operation_success = 0; // Flag to track the overall operation success

    // Initialize NFC context
    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "Unable to init libnfc (malloc).\n");
        exit(EXIT_FAILURE);
    }

    // Open NFC device
    device = nfc_open(context, NULL);
    if (device == NULL) {
        fprintf(stderr, "Unable to open NFC device.\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Discover MIFARE Tags
    tags = freefare_get_tags(device);
    if (!tags) {
        fprintf(stderr, "Error listing MIFARE Classic tags.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Open file for data storage
    fp = fopen("/home/elliot/Desktop/NFC/data_store/extracted_uid.txt", "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file for writing.\n");
        exit(EXIT_FAILURE);
    }

    // Iterate through discovered tags
    for (int i = 0; tags[i] != NULL; i++) {
        if (freefare_get_tag_type(tags[i]) == MIFARE_CLASSIC_1K) {
            MifareClassicKey default_key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

            if (mifare_classic_connect(tags[i]) < 0) {
                fprintf(stderr, "Can't connect to MIFARE Classic tag.\n");
                continue;
            }

            // Authenticate and read data from block 12
            int block = 12;
            if (mifare_classic_authenticate(tags[i], block, default_key, MFC_KEY_A) < 0) {
                fprintf(stderr, "Authentication failed for block %d.\n", block);
            } else {
                MifareClassicBlock data;
                if (mifare_classic_read(tags[i], block, &data) < 0) {
                    fprintf(stderr, "Read failed for block %d.\n", block);
                } else {
                    operation_success = 1; // Set success flag
                    for (int j = 0; j < 16; j++) {
                        // Decode as ASCII and write to file
                        if (data[j] >= 32 && data[j] <= 126) {
                            fprintf(fp, "%c", data[j]);
                        } else {
                            fprintf(fp, "."); // Placeholder for non-printable bytes
                        }
                    }
                    fprintf(fp, "\n");
                }
            }

            mifare_classic_disconnect(tags[i]);
        }
        freefare_free_tag(tags[i]);
    }

    // Cleanup and exit
    fclose(fp);
    free(tags);
    nfc_close(device);
    nfc_exit(context);
    return operation_success; // Return 1 if any read/write was successful, otherwise 0
}
