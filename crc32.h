#ifndef CRC_32_H
#define CRC_32_H

unsigned int crc32(const char* const input, unsigned int start = 0xffffffff);
unsigned int finishCrc32(unsigned int input);

#endif /* CRC_32_H */
