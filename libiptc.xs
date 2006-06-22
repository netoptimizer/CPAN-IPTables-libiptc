#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libiptc/libiptc.h>
#include <errno.h>

#include "const-c.inc"

#define ERROR_SV perl_get_sv("!", 0)
#define SET_ERRSTR(format...) sv_setpvf(ERROR_SV, ##format)
#define SET_ERRNUM(value) sv_setiv(ERROR_SV, (IV)value)

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
    handle  = iptc_init(tablename);
    if (handle == NULL) {
	RETVAL  = NULL;
	SET_ERRNUM(errno);
	SET_ERRSTR("%s", iptc_strerror(errno));
	SvIOK_on(ERROR_SV);
    } else {
	RETVAL  = malloc(sizeof(iptc_handle_t));
	*RETVAL = handle;
    }
  OUTPUT:
    RETVAL


int
create_chain(self, chain)
    IPTables::libiptc self
    char * chain
  CODE:
    RETVAL = iptc_create_chain(chain, self);
    if (!RETVAL) {
	SET_ERRNUM(errno);
	SET_ERRSTR("%s", iptc_strerror(errno));
	SvIOK_on(ERROR_SV);
    }
  OUTPUT:
    RETVAL


void
DESTROY(self)
    IPTables::libiptc &self
  CODE:
    if(self) {
	if(*self) iptc_free(self);
	free(self);
    }
