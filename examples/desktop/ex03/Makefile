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
PROGNAME=example3

all: main

main: main.c
	@echo "Compiling example ..."
	@$(CC) -Os -o $(PROGNAME) -fwhole-program -flto -fuse-linker-plugin main.c -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -L$(LIBDIR) -l$(LIBANAME) -lsodium
	@$(STRIP) $(PROGNAME)

.PHONY: clean
clean:
	@echo "Removing example ..."
	rm $(PROGNAME) -v


