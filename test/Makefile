CC=gcc
#LD=ld -r -b binary
INCLUDEDIR=$(PWD)/include/
INCLUDEDIRPRIVATE=$(PWD)/include/sodium/
INCLUDECTEST=$(PWD)/include/ctest
INCLUDEDIRTEST=$(PWD)/test/include
INCLUDECJSONTEST=$(PWD)/include/cjson
LIBANAME=nanocrypto1
WELCOMEMSG=welcome
WELCOMEMSGDIR=$(PWD)/test/resource/

LIBDIR=$(PWD)/lib

include ./project.mk

all: main

$(WELCOMEMSGDIR)$(WELCOMEMSG).o: $(WELCOMEMSGDIR)$(WELCOMEMSG).txt
	@echo "Linking ${WELCOMEMSG}.txt ..."
	sh $(PWD)/test/resource/buildobj.sh

main: $(CSRCS) $(WELCOMEMSGDIR)$(WELCOMEMSG).o
	@echo "Compiling test ..."
	@$(CC) -O2 -o test main.c $(WELCOMEMSGDIR)$(WELCOMEMSG).o $(CSRCS) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -I$(INCLUDEDIRTEST) -I$(INCLUDECTEST) -I$(INCLUDECJSONTEST) -L$(LIBDIR) -L$(PWD) -l$(LIBANAME) -lsodium -fsanitize=address,leak
	@echo "Executing test ..."
	./test

.PHONY: clean
clean:
	@echo "Cleaning test..."
	rm test -v
	@echo "Removing $(WELCOMEMSGDIR)$(WELCOMEMSG).o ..."
	rm $(WELCOMEMSGDIR)$(WELCOMEMSG).o -v

