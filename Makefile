#
#	AUTHOR: Fábio Pereira da Silva
#	YEAR: 2019
#	LICENSE: MIT
#	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
#

# Generating tools
#Qui 04 Jul 2019 00:09:11 -03 
CC=gcc
STRIP=strip
INCLUDEDIR=$(PWD)/include/
INCLUDEDIRPRIVATE=$(PWD)/include/sodium/
#LD=ld -r -b binary
AR=ar rcs
LIBANAME=nanocrypto1
#LIBSONAME=fcrypt1.1
CURDIR=$(PWD)
LIBDIR=$(CURDIR)/lib
ARCH?=F_IA64
LIBSODIUM_LIB=libsodium-1.0.18
#libsodium-1.0.17

include ./project.mk

OBJEXT ?= .o
EXAMPLE_OBJS ?= .o

SOBJS = $(SSRCS:.S=$(OBJEXT))
COBJS = $(CSRCS:.c=$(OBJEXT))

CEXOBJS = $(CEXSRCS:.c=$(EXAMPLE_OBJS))

all: part main

%.o: %.S
	#@$(CC) -c $< -o $@ -Os -D$(ARCH) -flto -fuse-linker-plugin -fwhole-program #PHP
	@$(CC) -c $< -o $@ -O2 -D$(ARCH) -flto -fuse-linker-plugin -fwhole-program -fPIC #Node/Java
	#@$(CC) -c $< -o $@ -Os -D$(ARCH) -fwhole-program
	@echo "Assembly $<"

%.o: %.c
	#@$(CC) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -c $< -o $@ -Os -D$(ARCH) -flto -fuse-linker-plugin -fwhole-program #PHP
	@$(CC) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -c $< -o $@ -O2 -D$(ARCH) -flto -fuse-linker-plugin -fwhole-program -fPIC #NODE/JAVA
	#@$(CC) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -c $< -o $@ -Os -D$(ARCH) -fwhole-program
	@echo "CC $<"

part:$(COBJS) $(SOBJS)
	@echo "Entering embedded data ..."
	$(MAKE) -C embedded

main: part
	@echo "Almost finishing ..."
	if [ ! -d $(CURDIR)/lib ]; then \
		@echo "lib directory does not exist. Creating ...";\
		mkdir $(CURDIR)/lib;\
	fi
	cd $(CURDIR)/src/$(LIBSODIUM_LIB) -v;\
	./configure --disable-pie --prefix=$(CURDIR)/src/$(LIBSODIUM_LIB)/build
	$(MAKE) -C $(CURDIR)/src/$(LIBSODIUM_LIB)
	$(MAKE) -C $(CURDIR)/src/$(LIBSODIUM_LIB) install
	mv $(CURDIR)/src/$(LIBSODIUM_LIB)/build/lib/libsodium.a $(CURDIR)/lib
	cd $(CURDIR) -v
	@echo "Creating static library..."
	$(AR) $(LIBDIR)/lib$(LIBANAME).a $(wildcard $(RAWDATDIR)/*.o) $(COBJS) $(SOBJS)
#	$(CC) -shared -o $(LIBDIR)/lib$(LIBANAME).so $(wildcard $(RAWDATDIR)/*.o) $(COBJS) $(SOBJS)

test: main
	$(MAKE) -C $(PWD)/test
	@echo "Test finished successfully"

examples: $(COBJS) $(SOBJS) $(CEXOBJS)
	@echo "Making examples ..."
	cd $(CURDIR)/src/$(LIBSODIUM_LIB) -v;\
	./configure --prefix=$(CURDIR)/src/$(LIBSODIUM_LIB)/build
	$(MAKE) -C $(CURDIR)/src/$(LIBSODIUM_LIB)
	$(MAKE) -C $(CURDIR)/src/$(LIBSODIUM_LIB) install
	mv $(CURDIR)/src/$(LIBSODIUM_LIB)/build/lib/libsodium.a $(CURDIR)/lib
	cd $(CURDIR) -v
	@echo "Creating static library..."
	$(AR) $(LIBDIR)/lib$(LIBANAME).a $(wildcard $(RAWDATDIR)/*.o) $(COBJS) $(SOBJS)
	cd $(CURDIR)/examples/desktop/ex01/
	@echo $(PWD)
	$(MAKE) -C examples/desktop/ex01
	cd $(CURDIR)/examples/desktop/ex02
	$(MAKE) -C examples/desktop/ex02

.PHONY: clean
clean:
	@echo "Entering $(RAWDATDIR)..."
	$(MAKE) -C embedded clean
	rm $(LIBDIR)/*.a -v
	@echo "Removing program objs ..."
	rm -v $(COBJS)
	rm -v $(SOBJS)
	$(MAKE) -C $(CURDIR)/src/$(LIBSODIUM_LIB) distclean
	rm -rfv $(CURDIR)/src/$(LIBSODIUM_LIB)/build
ifneq ("$(wildcard $(CURDIR)/test/test)","")
	@echo "Removing $(CTEST_DIR)/test/test ..."
	rm $(CURDIR)/test/test
endif

