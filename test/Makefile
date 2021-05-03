CC=gcc
INCLUDEDIR=$(PWD)/include/
INCLUDEDIRPRIVATE=$(PWD)/include/sodium/
INCLUDECTEST=$(PWD)/include/ctest
INCLUDEDIRTEST=$(PWD)/test/include
INCLUDECJSONTEST=$(PWD)/include/cjson
LIBANAME=nanocrypto1

LIBDIR=$(PWD)/lib

include ./project.mk

all: main

main: $(CSRCS)
	@echo "Compiling test ..."
	@$(CC) -O2 -o test main.c $(CSRCS) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -I$(INCLUDEDIRTEST) -I$(INCLUDECTEST) -I$(INCLUDECJSONTEST) -L$(LIBDIR) -L$(PWD) -l$(LIBANAME) -lsodium -fsanitize=address,leak
	@echo "Executing test ..."
	./test

.PHONY: clean
clean:
	@echo "Cleaning test..."
	rm test -v


