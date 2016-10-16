#include "sha256.h"
#include <string.h>

unsigned char*
sha256(unsigned char input[], unsigned int inputLength)
{
    static unsigned char result[SHA256_BLOCK_SIZE];
    unsigned int m[64];
    unsigned int k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
        0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
        0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
        0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
        0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    unsigned int state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned char data[64];
    unsigned int bitLength[2] = {0, 0};
    unsigned int dataLength = 0;
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    unsigned int e;
    unsigned int f;
    unsigned int g;
    unsigned int h;
    unsigned int t1;
    unsigned int t2;
    unsigned int index;
    unsigned int index2;

    index = 0;
    while (index < inputLength) {
        data[dataLength] = input[index];
        ++dataLength;
        if (dataLength >= 64) {
            index2 = 0;
            while (index2 < 16) {
                m[index2] = static_cast<unsigned int>((data[index2 * 4] << 24) |
                    (data[index2 * 4 + 1] << 16) |
                    (data[index2 * 4 + 2] << 8) |
                    (data[index2 * 4 + 3]));
                ++index2;
            }
            while (index2 < 64) {
                m[index2] =
                    ( ((m[index2 - 2] >> 17) | (m[index2 - 2] << 15)) ^
                      ((m[index2 - 2] >> 19) | (m[index2 - 2] << 13)) ^
                       (m[index2 - 2] >> 10) ) + m[index2 - 7] +
                    ( ((m[index2 - 15] >> 7) | (m[index2 - 15] << 25)) ^
                      ((m[index2 - 15] >> 18) | (m[index2 - 15] << 14)) ^
                       (m[index2 - 15] >> 3)) + m[index2 - 16];
                ++index2;
            }
            a = state[0];
            b = state[1];
            c = state[2];
            d = state[3];
            e = state[4];
            f = state[5];
            g = state[6];
            h = state[7];
            index2 = 0;
            while (index2 < 64) {
                t1 = ( ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                        ((e >> 25) | (e << 7)) ) +
                    ((e & f) ^ (~e & g)) + k[index2] + m[index2] + h;
                t2 = ( ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                       ((a >> 22) | (a << 10)) ) +
                    ((a & b) ^ (a & c) ^ (b & c));
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
                ++index2;
            }
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;

            if (bitLength[0] > 4294966783) {
                ++bitLength[1];
            }
            bitLength[0] += 512;

            dataLength = 0;
        }
        ++index;
    }

    index = dataLength;
    if (dataLength < 56) {
        data[index] = 0x80;
        ++index;
        while (index < 56) {
            data[index] = 0x00;
            ++index;
        }
    } else {
        data[index] = 0x80;
        ++index;
        while (index < 64) {
            data[index] = 0x00;
            ++index;
        }

        index2 = 0;
        while (index2 < 16) {
            m[index2] = static_cast<unsigned int>((data[index2 * 4] << 24) |
                (data[index2 * 4 + 1] << 16) |
                (data[index2 * 4 + 2] << 8) |
                (data[index2 * 4 + 3]));
            ++index2;
        }
        while (index2 < 64) {
            m[index2] =
                ( ((m[index2 - 2] >> 17) | (m[index2 - 2] << 15)) ^
                  ((m[index2 - 2] >> 19) | (m[index2 - 2] << 13)) ^
                   (m[index2 - 2] >> 10) ) + m[index2 - 7] +
                ( ((m[index2 - 15] >> 7) | (m[index2 - 15] << 25)) ^
                  ((m[index2 - 15] >> 18) | (m[index2 - 15] << 14)) ^
                   (m[index2 - 15] >> 3)) + m[index2 - 16];
            ++index2;
        }
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];
        index2 = 0;
        while (index2 < 64) {
            t1 = ( ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                    ((e >> 25) | (e << 7)) ) +
                ((e & f) ^ (~e & g)) + k[index2] + m[index2] + h;
            t2 = ( ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
                   ((a >> 22) | (a << 10)) ) +
                ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
            ++index2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;

        memset(data, 0, 56);
    }
    if (bitLength[0] > 4294967295 - dataLength * 8) {
        ++bitLength[1];
    }
    bitLength[0] += dataLength * 8;
    data[63] = bitLength[0];
    data[62] = bitLength[0] >> 8;
    data[61] = bitLength[0] >> 16;
    data[60] = bitLength[0] >> 24;
    data[59] = bitLength[1];
    data[58] = bitLength[1] >> 8;
    data[57] = bitLength[1] >> 16;
    data[56] = bitLength[1] >> 24;

    index2 = 0;
    while (index2 < 16) {
        m[index2] = static_cast<unsigned int>((data[index2 * 4] << 24) |
            (data[index2 * 4 + 1] << 16) |
            (data[index2 * 4 + 2] << 8) |
            (data[index2 * 4 + 3]));
        ++index2;
    }
    while (index2 < 64) {
        m[index2] =
            ( ((m[index2 - 2] >> 17) | (m[index2 - 2] << 15)) ^
              ((m[index2 - 2] >> 19) | (m[index2 - 2] << 13)) ^
               (m[index2 - 2] >> 10) ) + m[index2 - 7] +
            ( ((m[index2 - 15] >> 7) | (m[index2 - 15] << 25)) ^
              ((m[index2 - 15] >> 18) | (m[index2 - 15] << 14)) ^
               (m[index2 - 15] >> 3)) + m[index2 - 16];
        ++index2;
    }
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    index2 = 0;
    while (index2 < 64) {
        t1 = ( ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^
                ((e >> 25) | (e << 7)) ) +
            ((e & f) ^ (~e & g)) + k[index2] + m[index2] + h;
        t2 = ( ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^
               ((a >> 22) | (a << 10)) ) +
            ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
        ++index2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    index = 0;
    while (index < 4) {
        result[index] = state[0] >> (24 - index * 8) & 0x000000ff;
        result[index + 4] = state[1] >> (24 - index * 8) & 0x000000ff;
        result[index + 8] = state[2] >> (24 - index * 8) & 0x000000ff;
        result[index + 12] = state[3] >> (24 - index * 8) & 0x000000ff;
        result[index + 16] = state[4] >> (24 - index * 8) & 0x000000ff;
        result[index + 20] = state[5] >> (24 - index * 8) & 0x000000ff;
        result[index + 24] = state[6] >> (24 - index * 8) & 0x000000ff;
        result[index + 28] = state[7] >> (24 - index * 8) & 0x000000ff;
        ++index;
    }

    return result;
}
