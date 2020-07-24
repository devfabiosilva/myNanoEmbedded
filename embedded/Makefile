#Qui 04 Jul 2019 00:09:11 -03 
LD=ld -r -b binary

include ../project.mk

OBJEXT ?= .o

#RAWDAT+=teste.dat
OBJDATA=$(RAWDAT:.dat=$(OBJEXT))

%.o: %.dat
	@$(LD) $< -o $@
	@echo "FIOT linking data: LD $< --> $@"

main:$(OBJDATA)
	@echo "FIOT linked data success"

.PHONY: clean
clean:
	@echo "Removing all data objs..."
	rm -v $(OBJDATA)

