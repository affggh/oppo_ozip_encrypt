CC = gcc
LD = gcc
AR = ar
STRIP = strip
# CFLAGS = -O3 -DSHOW_PROGRESS
CFLAGS = -O3

default : all

ozip2zip : ozip_encrypt.c libprogressbar.a
	$(CC) $(CFLAGS) -Iprogressbar/include/progressbar ozip_encrypt.c tiny-AES-c/aes.c  -o zip2ozip libprogressbar.a -lcrypto -lncurses
	$(STRIP) zip2ozip

libprogressbar.a :
	cd progressbar && $(MAKE) libprogressbar.a
	mv progressbar/libprogressbar.a ./

all : ozip2zip

clean:
	rm -f *.o zip2ozip
	rm -f *.a
	cd progressbar && $(MAKE) clean
