#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <libiptc/libiptc.h>

#include "const-c.inc"

MODULE = IPTables::libiptc		PACKAGE = IPTables::libiptc

INCLUDE: const-xs.inc
