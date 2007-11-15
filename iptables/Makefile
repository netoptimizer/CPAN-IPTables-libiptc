#
# Makefile for making a iptables.o file...
#

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif

ifndef IPTABLES_VERSION
IPTABLES_VERSION:=1.3.4
endif

ifndef PREFIX
PREFIX:=/usr/local/
endif

LIBDIR:=$(PREFIX)/lib
INCDIR:=$(PREFIX)/include

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif

ifndef LDFLAGS
LDFLAGS = -L$(LIBDIR)
endif
LDFLAGS+=-rdynamic

# Local version of libiptc
# ($(LOCAL_LIB_IPTC) cannot be used here because it needs a "../")
LD_LOCAL_IPTC:=-L../library_iptc/

LDLIBS=-liptc -ldl -lnsl

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include -I$(INCDIR) -I../include/
#-g -DDEBUG #-pg # -DIPTC_DEBUG

DEFINES:=-DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -DIPT_LIB_DIR=\"$(IPT_LIBDIR)\"
default: all

all: iptables.o iptables-standalone

iptables.o: iptables.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

iptables-standalone: iptables-standalone.c iptables.o
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) $(LD_LOCAL_IPTC) -o $@ $^ $(LDLIBS)

clean:
	rm iptables-standalone *.o
