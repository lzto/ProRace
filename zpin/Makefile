# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif
include $(CONFIG_ROOT)/makefile.config
#include Makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules

all: zp

zp:
	make obj-intel64/zp.so

clean:
	rm -rf obj-ia32/ obj-intel64/ *.out* *.log* *.xml *.makefile.copy *.core
	rm -f child_asm.out  child.out  child_reg.out  child_r.out  child_w.out  parent_asm.out  parent.out  parent_reg.out  parent_r.out  parent_w.out
	rm -f asm.diff  mem_r.diff  mem_w.diff  reg.diff
	rm -f chk_log.out
	rm -f $(BINARIES) $(BITCODES)

test:
	gcc hew.c -o hew

