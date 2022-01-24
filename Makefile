CC = gcc
LD = gcc
AR = ar
STRIP = strip
CFLAGS = -Werror -O3

default : all

ozip2zip : ozip_encrypt.c
	$(CC) $(CFLAGS) ozip_encrypt.c tiny-AES-c/aes.c -o zip2ozip -lcrypto
	$(STRIP) zip2ozip

all : ozip2zip

clean:
	rm -f *.o zip2ozip