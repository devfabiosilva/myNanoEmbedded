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

include ./project.mk

OBJEXT ?= .o

SOBJS = $(SSRCS:.S=$(OBJEXT))
COBJS = $(CSRCS:.c=$(OBJEXT))

all: part main

%.o: %.S
	@$(CC) -c $< -o $@ -Os -D$(ARCH)
	@echo "Assembly $<"

%.o: %.c
	@$(CC) -I$(INCLUDEDIR) -I$(INCLUDEDIRPRIVATE) -c $< -o $@ -Os -D$(ARCH)
	@echo "CC $<"

part:$(COBJS) $(SOBJS)
	@echo "Entering embedded data ..."
	$(MAKE) -C embedded

main: part
	@echo "Almost finishing ..."
	cd $(CURDIR)/src/libsodium-1.0.17 -v;\
	./configure --prefix=$(CURDIR)/src/libsodium-1.0.17/build
	$(MAKE) -C $(CURDIR)/src/libsodium-1.0.17
	$(MAKE) -C $(CURDIR)/src/libsodium-1.0.17 install
	mv $(CURDIR)/src/libsodium-1.0.17/build/lib/libsodium.a $(CURDIR)/lib
	cd $(CURDIR) -v
	@echo "Creating static library..."
	$(AR) $(LIBDIR)/lib$(LIBANAME).a $(wildcard $(RAWDATDIR)/*.o) $(COBJS) $(SOBJS)

.PHONY: clean
clean:
	@echo "Entering $(RAWDATDIR)..."
	$(MAKE) -C embedded clean
	rm $(LIBDIR)/*.a -v
	@echo "Removing program objs ..."
	rm -v $(COBJS)
	rm -v $(SOBJS)
	$(MAKE) -C $(CURDIR)/src/libsodium-1.0.17 distclean
	rm -rfv $(CURDIR)/src/libsodium-1.0.17/build


