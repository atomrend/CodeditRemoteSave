#include "crc32.h"

unsigned int
crc32(const char* const input, unsigned int start)
{
    unsigned int result = start;
    unsigned int byte;
    int index = 0;
    unsigned char index2;

    byte = static_cast<unsigned int>(input[index]);
    while (byte != 0) {
        byte = ((byte & 0x55555555) <<  1) | ((byte >>  1) & 0x55555555);
        byte = ((byte & 0x33333333) <<  2) | ((byte >>  2) & 0x33333333);
        byte = ((byte & 0x0f0f0f0f) <<  4) | ((byte >>  4) & 0x0f0f0f0f);
        byte = (byte << 24) | ((byte & 0xff00) << 8) |
            ((byte >> 8) & 0xff00) | (byte >> 24);

        index2 = 0;
        while (index2 < 8) {
            if (((result ^ byte) & 0x80000000) != 0) {
                result = (result << 1) ^ 0x04c11db7;
            } else {
                result = result << 1;
            }
            byte = byte << 1;

            ++index2;
        }

        ++index;
        byte = static_cast<unsigned int>(input[index]);
    }

    return result;
}


unsigned int
finishCrc32(unsigned int input)
{
    input = ~input;
    input = ((input & 0x55555555) <<  1) | ((input >>  1) & 0x55555555);
    input = ((input & 0x33333333) <<  2) | ((input >>  2) & 0x33333333);
    input = ((input & 0x0f0f0f0f) <<  4) | ((input >>  4) & 0x0f0f0f0f);
    input = (input << 24) | ((input & 0xff00) << 8) |
        ((input >> 8) & 0xff00) | (input >> 24);

    return input;
}
