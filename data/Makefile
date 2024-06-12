# Notes on this shit show:
# - DWP=dwp make
#   - this causes `strace gdb test-stable-addrs.make --eval-command=quit` to at
#     least LOOK AT the DWP file (though it fails to load it)
# - DWP=llvm-dwp make
#   - this hangs `llvm-dwp` with 100% core utilization. ROFL
#   - that seems to be caused by (implicit) usage of DWARF 5
#   - with `-gdwarf-4` shit seems to just work
# - CC=clang DWP=llvm-dwp make
#   - gdb doesn't even attempt to look at DWP file

CC ?= gcc
LD ?= ld
OBJCOPY ?= objcopy
DWP ?= llvm-dwp

.PHONY: all
all: DIR := $(shell mktemp -d)
#all: CFLAGS := 
all: CFLAGS := -gdwarf-4
all:
	$(CC) -c -O0 -g -gsplit-dwarf $(CFLAGS) test-stable-addrs.c -o $(DIR)/test-stable-addrs.make.o
	$(CC) -c -O0 -g -gsplit-dwarf $(CFLAGS) test-stable-addrs-cu2.c -o $(DIR)/test-stable-addrs-cu2.make.o
	$(LD) -T test-stable-addrs.ld $(DIR)/test-stable-addrs.make.o $(DIR)/test-stable-addrs-cu2.make.o -o test-stable-addrs.make
	#objcopy test-stable-addrs.make test-stable-addrs.make
	#strip --remove-section=".debug*" --keep-section=.debug_info --keep-section=.debug_gnu_pubtypes --keep-section=.debug_gnu_pubnames test-stable-addrs.make
	#strip --remove-section=".debug_addr" test-stable-addrs.make
	$(DWP) $(DIR)/test-stable-addrs.make.dwo $(DIR)/test-stable-addrs-cu2.make.dwo -o test-stable-addrs.make.dwp
	rm -r $(DIR)
