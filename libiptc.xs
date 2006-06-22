#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libiptc/libiptc.h>
#include <errno.h>

#include "const-c.inc"

typedef iptc_handle_t* IPTables__libiptc;

MODULE = IPTables::libiptc		PACKAGE = IPTables::libiptc

INCLUDE: const-xs.inc

int
is_chain(self, chain)
    IPTables::libiptc self
    char * chain
  CODE:
    RETVAL = iptc_is_chain(chain, *self);
  OUTPUT:
    RETVAL


IPTables::libiptc
init(tablename)
    char * tablename
  PREINIT:
    iptc_handle_t handle;
  CODE:
    handle = iptc_init(tablename);
    RETVAL = malloc(sizeof(iptc_handle_t));
    *RETVAL = handle;
  OUTPUT:
    RETVAL
