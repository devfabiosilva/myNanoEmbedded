#Thu July 04 2019 00:09:11 -03 
LD=ld -r -b binary

include ../project.mk

OBJEXT ?= .o

OBJDATA=$(RAWDAT:.dat=$(OBJEXT))

%.o: %.dat
	@$(LD) $< -o $@
	@echo "myNanoEmbedded linking data: LD $< --> $@"

main:$(OBJDATA)
	@echo "myNanoEmbedded linked data success"

.PHONY: clean
clean:
	@echo "Removing all data objs..."
	rm -v $(OBJDATA)

