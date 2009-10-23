#
# Makefile for making a iptables.o file...
#

ifndef KERNEL_DIR
KERNEL_DIR=/usr/src/linux
endif

ifndef IPTABLES_VERSION
IPTABLES_VERSION:=1.4.1
endif

ifndef PREFIX
PREFIX:=/usr/local/
endif

LIBDIR:=$(PREFIX)/lib
INCDIR:=$(PREFIX)/include
SBINDIR:=$(PREFIX)/sbin

ifndef IPT_LIBDIR
IPT_LIBDIR:=$(LIBDIR)/iptables
endif

ifndef LDFLAGS
LDFLAGS = -L$(LIBDIR)
endif
LDFLAGS+=-rdynamic

# Local version of libiptc
# ($(LOCAL_LIB_IPTC) cannot be used here because it needs a "../")
#LD_LOCAL_IPTC:=-L../library_iptc/
#
# Need to link directly with object library
LOCAL_IPTC_OBJ:=../library_iptc/libiptc.a

#LDLIBS=-liptc -ldl -lnsl
LDLIBS=-ldl -lnsl

COPT_FLAGS:=-O2
CFLAGS:=$(COPT_FLAGS) -Wall -Wunused -I$(KERNEL_DIR)/include -I$(INCDIR) -I../include/ -fPIC -DXTABLES_INTERNAL
#-g -DDEBUG #-pg # -DIPTC_DEBUG

DEFINES:=-DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -DXTABLES_LIBDIR=\"$(XTABLES_LIBDIR)\"
default: all

all: iptables.o xtables.o iptables-standalone iptables-blocking

iptables.o: iptables.c Makefile
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

xtables.o: xtables.c Makefile
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

iptables-standalone: iptables-standalone.c iptables.o xtables.o
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $^ $(LOCAL_IPTC_OBJ) $(LDLIBS)

iptables-blocking: iptables-blocking.c iptables.o xtables.o
	$(CC) $(CFLAGS) $(DEFINES) $(LDFLAGS) -o $@ $^ $(LOCAL_IPTC_OBJ) $(LDLIBS)

install:
	install -m 0755 -d $(DESTDIR)/$(SBINDIR)
	install -m 0755 iptables-blocking $(DESTDIR)/$(SBINDIR)

clean:
	rm iptables-standalone iptables-blocking *.o
