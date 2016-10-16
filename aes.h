#ifndef AES_H
#define AES_H

#define AES_BLOCK_SIZE 16
#define AES_KEY_SCHEDULE_SIZE 60
#define AES_KEY_SIZE 32
#define USE_AES_ENCRYPT

void aesKeySetup(
    unsigned int output[AES_KEY_SCHEDULE_SIZE],
    const unsigned char key[AES_KEY_SIZE]);

#ifdef USE_AES_ENCRYPT
void aesEncrypt(
    unsigned char output[AES_BLOCK_SIZE],
    const unsigned char input[AES_BLOCK_SIZE],
    const unsigned int keySchedule[AES_KEY_SCHEDULE_SIZE]);
#endif /* USE_AES_ENCRYPT */

void aesDecrypt(
    unsigned char output[AES_BLOCK_SIZE],
    const unsigned char input[AES_BLOCK_SIZE],
    const unsigned int keySchedule[AES_KEY_SCHEDULE_SIZE]);

#endif /* AES_H */
