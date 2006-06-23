#
# Makefile for making a iptables.o file...
#

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif

IPTABLES_VERSION:=1.3.5
OLD_IPTABLES_VERSION:=1.3.4

ifndef PREFIX
PREFIX:=/usr/local/stow
endif

LIBDIR:=$(PREFIX)/lib
INCDIR:=$(PREFIX)/include

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif


COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include -I$(INCDIR) -I../include/ -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\"
#-g -DDEBUG #-pg # -DIPTC_DEBUG

default: all

all: iptables.o

iptables.o: iptables.c
        $(CC) $(CFLAGS) -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\" -c -o $@ $<

clean:
	rm *.o *~
