MODULE=CodeditRemoteSave
EXECUTABLE=CodeditRemoteSave

LIBS=-lpthread

SOURCES= \
    aes.c \
    crc32.c \
    main.c \
    sha256.c \

include Makefile.template
