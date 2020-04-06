#
#	AUTHOR: Fábio Pereira da Silva
#	YEAR: 2019
#	LICENSE: MIT
#	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
#

CC=gcc
STRIP=strip
INCLUDEDIR=$(PWD)/../../../include/
INCLUDEDIRPRIVATE=$(PWD)/../../../include/sodium/
LIBANAME=nanocrypto1
CURDIR=$(PWD)
LIBDIR=$(CURDIR)/../../../lib
PROGNAME=example6

all: main

main: main.c
	@echo "Compiling example ..."
	@$(CC) -Os -o $(PROGNAME) main.c -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -L$(LIBDIR) -lnanocrypto1 -lsodium -Wno-unused-result
	@$(STRIP) $(PROGNAME)

.PHONY: clean
clean:
	@echo "Removing example ..."
	rm $(PROGNAME) -v


