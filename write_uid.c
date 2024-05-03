#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <nfc/nfc.h>
#include <freefare.h>

int main(void) {
    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    nfc_context *context;
    char data_to_write[8 + 1]; // Buffer to hold 8 bytes of data + null terminator

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

    // Opens the .txt file containing the data to write
    FILE *file = fopen("/home/elliot/Desktop/nfc/data_store/uid.txt", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening data file.\n");
        exit(EXIT_FAILURE);
    }
    if (!fgets(data_to_write, sizeof(data_to_write), file)) {
        fprintf(stderr, "Failed to read data.\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);

    int block_to_write = 12; // Block where data will be written

    for (int i = 0; (!(tags[i] == NULL)); i++) {
        if (freefare_get_tag_type(tags[i]) == MIFARE_CLASSIC_1K) {
            MifareClassicKey default_key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

            if (mifare_classic_connect(tags[i]) < 0) {
                fprintf(stderr, "Can't connect to MIFARE Classic tag.\n");
                continue;
            }

            if (mifare_classic_authenticate(tags[i], block_to_write, default_key, MFC_KEY_A) < 0) {
                fprintf(stderr, "Authentication failed for block.\n");
            } else {
                char block_data[16] = {0};
                strncpy(block_data, data_to_write, 8); // Only copy the first 8 characters

                if (mifare_classic_write(tags[i], block_to_write, (unsigned char*)block_data) < 0) {
                    fprintf(stderr, "Write failed for block.\n");
                } else {
                    printf("Successfully wrote to block.\n");
                }
            }

            mifare_classic_disconnect(tags[i]);
        }
        freefare_free_tag(tags[i]);
    }

    nfc_close(device);
    nfc_exit(context);
    return 0;
}