#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <nfc/nfc.h>
#include <freefare.h>

int main(void) {
    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    nfc_context *context;
    char base64_data[128];  // Buffer size larger than the Base64 string to accommodate null terminator

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

    // Opens the .bin file containing the base64 cryptographic signature
    FILE *file = fopen("/home/elliot/Desktop/nfc/data_store/b64_signature.bin", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening Base64 signature file.\n");
        exit(EXIT_FAILURE);
    }
    if (!fgets(base64_data, sizeof(base64_data), file)) {
        fprintf(stderr, "Failed to read Base64 data.\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);

    int blocks_to_write[] = {4, 5, 6, 8, 9, 10}; // Amount & specific blocks needed to write to. (96bytes total)

    for (int i = 0; (!(tags[i] == NULL)); i++) {
        if (freefare_get_tag_type(tags[i]) == MIFARE_CLASSIC_1K) {
            MifareClassicKey default_key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // The defualt passowrd to a Mifare Classic Card: 000000

            if (mifare_classic_connect(tags[i]) < 0) {
                fprintf(stderr, "Can't connect to MIFARE Classic tag.\n");
                continue;
            }

            for (int j = 0; j < sizeof(blocks_to_write) / sizeof(blocks_to_write[0]); j++) { // Iterates over each block to write
                int block = blocks_to_write[j]; // Assings the current block to write to

                if (mifare_classic_authenticate(tags[i], block, default_key, MFC_KEY_A) < 0) { // Authenticates current block
                    fprintf(stderr, "Authentication failed for block %d.\n", block);
                    continue;
                }


                char block_data[16] = {0}; // clears block data
                int data_length = strlen(base64_data); // reads the data length of the base64 signature
                int offset = j * 16; // divides the data length by 16 (for each block)
                if (offset < data_length) { // Offset used to initialize where to start copying data from to the array (j changes each iteration)
                    strncpy(block_data, base64_data + offset, 16); // data is copied
                }

                if (mifare_classic_write(tags[i], block, (unsigned char*)block_data) < 0) { // Writes that data to the current block
                    fprintf(stderr, "Write failed for block %d.\n", block);
                } else {
                    printf("Successfully wrote to block %d.\n", block);
                }
            }

            mifare_classic_disconnect(tags[i]); // current tag is disconnected
        }
        freefare_free_tag(tags[i]); // data allocated tp that tag is freed.
    }

    nfc_close(device);
    nfc_exit(context);
    return 0;
}