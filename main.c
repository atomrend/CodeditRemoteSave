#include "aes.h"
#include <arpa/inet.h>
#include "crc32.h"
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>
#include <pthread.h>
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1440
#define THREAD_COUNT 4
#define SETUP_FILE_PATH "/etc/remoteCodeditSave.txt"
#define ADDRESS_INFO_FILE_PATH "/var/run/remoteCodeditSaveInfo.txt"
#define SUCESS "0"
#define FAILED_CONNECTION "1"
#define FAILED_TIME_OUT "2"
#define FAILED_AUTHENTICATION "3"
#define FAILED_FILE_PATH_TOO_LONG "4"
#define FAILED_CANNOT_OPEN_FILE "5"
#define FAILED_BAD_FILE_SIZE "6"
#define FAILED_CHECKSUM "7"
#define FAILED_ACTION "8"
#define FAILED_PORT "9"
#define FAILED_ADDRESS "10"

typedef struct ThreadData {
    unsigned char privateKey[SHA256_BLOCK_SIZE];
    unsigned char passwordHash[SHA256_BLOCK_SIZE];
    int serverSocket;
} ThreadData;

void generatePublicKey(unsigned char output[SHA256_BLOCK_SIZE]);
void convertHexTextToKeyBlock(unsigned char output[SHA256_BLOCK_SIZE],
    const char* text);
void* threadFunc(void* args);

void*
threadFunc(void* args)
{
    char buffer[BUFFER_SIZE + 1];
    unsigned char publicKey[SHA256_BLOCK_SIZE];
    unsigned char authenticate[SHA256_BLOCK_SIZE];
    unsigned char aesKey[SHA256_BLOCK_SIZE];
    unsigned int aesKeySchedule[AES_KEY_SCHEDULE_SIZE];
    unsigned char aesEncrypted[AES_BLOCK_SIZE];
    unsigned char aesDecrypted[AES_BLOCK_SIZE];
    struct sockaddr_in clientAddress;
    ThreadData *threadData = reinterpret_cast<ThreadData*>(args);
    char *path = 0;
    FILE *handle = 0;
    socklen_t clientSize = sizeof(clientAddress);
    unsigned int fileSize;
    unsigned int pathSize;
    unsigned int receivedChecksum;
    unsigned int currCrc;
    unsigned int actionSize;
    unsigned int tmpNumber;
    int clientSocket;
    int size;
    int tmp;
    char valid;

    while ((clientSocket = accept(threadData->serverSocket,
            reinterpret_cast<struct sockaddr*>(&clientAddress),
            &clientSize)) >= 0) {
        free(path);
        path = 0;

        generatePublicKey(publicKey);
        send(clientSocket, publicKey, SHA256_BLOCK_SIZE, 0);

        size = 0;
        while (size < SHA256_BLOCK_SIZE) {
            authenticate[size] = threadData->privateKey[size] ^
                threadData->passwordHash[size] ^ publicKey[size];
            ++size;
        }
        memcpy(authenticate, sha256(authenticate, SHA256_BLOCK_SIZE),
            SHA256_BLOCK_SIZE);
        size = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (size >= SHA256_BLOCK_SIZE) {
            valid = memcmp(authenticate, buffer, SHA256_BLOCK_SIZE) == 0;
        } else {
            valid = 0;
        }
        if (valid != 0) {
            memset(buffer, '\0', 2);
            snprintf(buffer, BUFFER_SIZE, SUCESS);
            size = send(clientSocket, buffer, 2, 0);
            valid = 1;
        } else {
            memset(buffer, '\0', 2);
            snprintf(buffer, BUFFER_SIZE, FAILED_AUTHENTICATION);
            size = send(clientSocket, buffer, 2, 0);
            valid = 0;
        }

        if (valid == 1) {
            size = 0;
            while (size < SHA256_BLOCK_SIZE) {
                aesKey[size] = threadData->passwordHash[size] ^ publicKey[size];
                ++size;
            }
            memcpy(aesKey, sha256(aesKey, SHA256_BLOCK_SIZE),
                SHA256_BLOCK_SIZE);
            aesKeySetup(aesKeySchedule, aesKey);

            size = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        }

        if (valid == 1 && size >= 16) {
            tmp = 0;
            while (tmp < size) {
                memcpy(aesEncrypted, buffer + tmp, AES_BLOCK_SIZE);
                aesDecrypt(aesDecrypted, aesEncrypted, aesKeySchedule);
                memcpy(buffer + tmp, aesDecrypted, AES_BLOCK_SIZE);
                tmp += AES_BLOCK_SIZE;
            }
            
            size = 0;
            memcpy(&tmpNumber, buffer + size, sizeof(unsigned int));
            fileSize = ntohl(tmpNumber);
            size += static_cast<int>(sizeof(unsigned int));

            memcpy(&tmpNumber, buffer + size, sizeof(unsigned int));
            actionSize = ntohl(tmpNumber);
            size += static_cast<int>(sizeof(unsigned int));

            memcpy(&tmpNumber, buffer + size, sizeof(unsigned int));
            receivedChecksum = ntohl(tmpNumber);
            size += static_cast<int>(sizeof(unsigned int));

            memcpy(&tmpNumber, buffer + size, sizeof(unsigned int));
            pathSize = ntohl(tmpNumber);
            size += static_cast<int>(sizeof(unsigned int));

            path = static_cast<char*>(malloc(pathSize * sizeof(char)));
            memset(path, '\0', pathSize);
            strncpy(path, buffer + size, pathSize - 1);
        } else {
            valid = 0;
        }

        if (valid == 1) {
            handle = fopen(path, "w");
            if (handle == 0) {
                valid = 0;
                snprintf(buffer, BUFFER_SIZE, FAILED_CANNOT_OPEN_FILE);
                size = send(clientSocket, buffer, 2, 0);
            } else {
                snprintf(buffer, BUFFER_SIZE, SUCESS);
                size = send(clientSocket, buffer, 2, 0);
            }
        }

        if (valid == 1) {
            currCrc = 0xffffffff;
            tmpNumber = 0;
            while (tmpNumber < fileSize) {
                memset(buffer, '\0', BUFFER_SIZE + 1);
                size = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                buffer[size] = '\0';

                // Decrypt the packet.
                tmp = 0;
                while (tmp < size) {
                    memcpy(aesEncrypted, buffer + tmp, AES_BLOCK_SIZE);
                    aesDecrypt(aesDecrypted, aesEncrypted, aesKeySchedule);
                    memcpy(buffer + tmp, aesDecrypted, AES_BLOCK_SIZE);

                    tmp += AES_BLOCK_SIZE;
                }

                // Save it to the file.
                tmp = size;
                if (tmpNumber + static_cast<unsigned int>(tmp) > fileSize) {
                    tmp = static_cast<int>(fileSize - tmpNumber);
                }
                buffer[tmp] = 0;
                currCrc = crc32(buffer, currCrc);
                fwrite(buffer, sizeof(char), static_cast<unsigned int>(tmp),
                    handle);
                tmpNumber += static_cast<unsigned int>(tmp);

                snprintf(buffer, BUFFER_SIZE, SUCESS);
                size = send(clientSocket, buffer, 2, 0);
            }
            currCrc = finishCrc32(currCrc);

            fclose(handle);

            handle = fopen(path, "r");
            fseek(handle, 0, SEEK_END);
            tmpNumber = static_cast<unsigned int>(ftell(handle));
            fclose(handle);

            if (tmpNumber == fileSize && currCrc == receivedChecksum) {
                snprintf(buffer, BUFFER_SIZE, SUCESS);
                size = send(clientSocket, buffer, 2, 0);
            } else if (tmpNumber != fileSize) {
                valid = 0;
                snprintf(buffer, BUFFER_SIZE, FAILED_BAD_FILE_SIZE);
                size = send(clientSocket, buffer, 2, 0);
            } else {
                valid = 0;
                snprintf(buffer, BUFFER_SIZE, FAILED_CHECKSUM);
                size = send(clientSocket, buffer, 2, 0);
            }
        }

        if (valid == 1 && actionSize > 1) {
            size = recv(clientSocket, buffer, BUFFER_SIZE, 0);

            tmp = 0;
            while (tmp < size) {
                memcpy(aesEncrypted, buffer + tmp, AES_BLOCK_SIZE);
                aesDecrypt(aesDecrypted, aesEncrypted, aesKeySchedule);
                memcpy(buffer + tmp, aesDecrypted, AES_BLOCK_SIZE);

                tmp += AES_BLOCK_SIZE;
            }
            buffer[actionSize] = '\0';
            buffer[BUFFER_SIZE] = '\0';

            if (system(buffer) == 0) {
                snprintf(buffer, BUFFER_SIZE, SUCESS);
                size = send(clientSocket, buffer, 2, 0);
            } else {
                snprintf(buffer, BUFFER_SIZE, FAILED_ACTION);
                size = send(clientSocket, buffer, 2, 0);
            }
        }

        free(path);
        path = 0;

        close(clientSocket);
    }

    pthread_exit(0);
}

int
main()
{
    char host[NI_MAXHOST];
    ThreadData threadData;
    pthread_t threads[THREAD_COUNT];
    struct sockaddr_in serverAddress;
    struct ifaddrs *interfaces;
    struct ifaddrs *interfacePtr;
    FILE *handle;
    socklen_t serverSize = sizeof(serverAddress);
    int index = 0;
    unsigned short port = 0;

    srand(static_cast<unsigned int>(time(0)));

    index = socket(AF_INET, SOCK_STREAM, 0);
    if (index >= 0) {
        threadData.serverSocket = index;
    } else {
        fprintf(stderr, "Unable to create the server socket!\n");
        index = -1;
    }

    if (index != -1) {
        handle = fopen(SETUP_FILE_PATH, "r");
        if (handle != 0) {
            while (fgets(host, NI_MAXHOST, handle) != 0) {
                if (strncmp(host, "port=", 5) == 0) {
                    port = static_cast<unsigned short>(atoi(host + 5));
                } else if (strncmp(host, "privateKey=", 11) == 0) {
                    index = 0;
                    while (index < NI_MAXHOST) {
                        if (host[index] == '\n') {
                            host[index] = '\0';
                            break;
                        }
                        ++index;
                    }
                    if (host[11] == 'x') {
                        index = 12;
                    } else if (host[11] == '0' && host[12] == 'x') {
                        index = 13;
                    } else {
                        index = 11;
                    }
                    convertHexTextToKeyBlock(threadData.privateKey,
                        host + index);
                } else if (strncmp(host, "password=", 9) == 0) {
                    index = 0;
                    while (index < NI_MAXHOST) {
                        if (host[index] == '\n') {
                            host[index] = '\0';
                            break;
                        }
                        ++index;
                    }
                    memcpy(threadData.passwordHash,
                        sha256(reinterpret_cast<unsigned char*>(host + 9),
                            strlen(host + 9)), SHA256_BLOCK_SIZE);
                }
            }

            fclose(handle);
        } else {
            fprintf(stderr, "Unable to open the server setup file!\n");
            index = -1;
        }
    }

    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);

    if (index != -1) {
        index = bind(threadData.serverSocket,
            reinterpret_cast<struct sockaddr*>(&serverAddress),
            sizeof(serverAddress));
        if (index < 0) {
            fprintf(stderr, "Unable to bind the server socket!\n");
            index = -1;
        }
    }

    if (index != -1) {
        index = listen(threadData.serverSocket, 5);
        if (index < 0) {
            fprintf(stderr, "Unable to listen with the server socket!\n");
            index = -1;
        }
    }

    if (index != -1) {
        handle = fopen(ADDRESS_INFO_FILE_PATH, "w");

        if (handle != 0) {
            fprintf(handle, "pid=%u\n", getpid());
        }

        /* Print out the local IP addresses of the network interfaces. */
        if (getifaddrs(&interfaces) == 0) {
            for (interfacePtr = interfaces; interfacePtr != 0;
                    interfacePtr = interfacePtr->ifa_next) {
                if ((interfacePtr->ifa_addr->sa_family == AF_INET ||
                        interfacePtr->ifa_addr->sa_family == AF_INET6) &&
                        strcmp(interfacePtr->ifa_name, "lo") != 0) {
                    getnameinfo(
                        interfacePtr->ifa_addr,
                        interfacePtr->ifa_addr->sa_family == AF_INET ?
                            sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST, 0, 0, NI_NUMERICHOST);
                    if (interfacePtr->ifa_addr->sa_family == AF_INET) {
                        printf("address(IPv4)=%s\n", host);
                        if (handle != 0) {
                            fprintf(handle, "address(IPv4)=%s\n", host);
                        }
                    } else {
                        printf("address(IPv6)=%s\n", host);
                        if (handle != 0) {
                            fprintf(handle, "address(IPv6)=%s\n", host);
                        }
                    }
                }
            }
            freeifaddrs(interfaces);
        }

        /* Print out the port number used. */
        getsockname(threadData.serverSocket,
            reinterpret_cast<struct sockaddr*>(&serverAddress),
            &serverSize);
        printf("Port=%u\n", ntohs(serverAddress.sin_port));
        if (handle != 0) {
            fprintf(handle, "Port=%u\n", ntohs(serverAddress.sin_port));
            fclose(handle);
        }

        index = 0;
        while (index < THREAD_COUNT) {
            pthread_create(threads + index, 0, threadFunc,
                reinterpret_cast<void*>(&threadData));
            ++index;
        }

        index = 0;
        while (index < THREAD_COUNT) {
            pthread_join(threads[index], 0);
            ++index;
        }

        close(threadData.serverSocket);
    }

    return 0;
}

void
generatePublicKey(unsigned char output[SHA256_BLOCK_SIZE])
{
    unsigned int index = 0;

    while (index < SHA256_BLOCK_SIZE) {
        output[index] = static_cast<unsigned char>(rand() % 255);
        ++index;
    }
}

void
convertHexTextToKeyBlock(
    unsigned char output[SHA256_BLOCK_SIZE],
    const char* text)
{
    unsigned int index = 0;
    unsigned char top;
    unsigned char bottom;
    char curr;

    while (index < strlen(text) / 2 && index < SHA256_BLOCK_SIZE) {
        top = 0x00;
        bottom = 0x00;

        curr = text[index * 2];
        if (curr == '1') {
            top = 0x10;
        } else if (curr == '2') {
            top = 0x20;
        } else if (curr == '3') {
            top = 0x30;
        } else if (curr == '4') {
            top = 0x40;
        } else if (curr == '5') {
            top = 0x50;
        } else if (curr == '6') {
            top = 0x60;
        } else if (curr == '7') {
            top = 0x70;
        } else if (curr == '8') {
            top = 0x80;
        } else if (curr == '9') {
            top = 0x90;
        } else if (curr == 'a' || curr == 'A') {
            top = 0xa0;
        } else if (curr == 'b' || curr == 'B') {
            top = 0xb0;
        } else if (curr == 'c' || curr == 'C') {
            top = 0xc0;
        } else if (curr == 'd' || curr == 'D') {
            top = 0xd0;
        } else if (curr == 'e' || curr == 'E') {
            top = 0xe0;
        } else if (curr == 'f' || curr == 'F') {
            top = 0xf0;
        }

        if (index * 2 + 1 < strlen(text)) {
            curr = text[index * 2 + 1];
            if (curr == '1') {
                bottom = 0x0a;
            } else if (curr == '2') {
                bottom = 0x02;
            } else if (curr == '3') {
                bottom = 0x03;
            } else if (curr == '4') {
                bottom = 0x04;
            } else if (curr == '5') {
                bottom = 0x05;
            } else if (curr == '6') {
                bottom = 0x06;
            } else if (curr == '7') {
                bottom = 0x07;
            } else if (curr == '8') {
                bottom = 0x08;
            } else if (curr == '9') {
                bottom = 0x09;
            } else if (curr == 'a' || curr == 'A') {
                bottom = 0x0a;
            } else if (curr == 'b' || curr == 'B') {
                bottom = 0x0b;
            } else if (curr == 'c' || curr == 'C') {
                bottom = 0x0c;
            } else if (curr == 'd' || curr == 'D') {
                bottom = 0x0d;
            } else if (curr == 'e' || curr == 'E') {
                bottom = 0x0e;
            } else if (curr == 'f' || curr == 'F') {
                bottom = 0x0f;
            }
        }

        output[index] = top | bottom;

        ++index;
    }
}
