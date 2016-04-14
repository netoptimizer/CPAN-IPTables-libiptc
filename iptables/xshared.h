#include <xtables.h>

#if   XTABLES_VERSION_CODE < 7
#include "xshared.h-old"

#elif XTABLES_VERSION_CODE == 7
#include "xshared.h-v1.4.12"

#elif XTABLES_VERSION_CODE == 9
#include "xshared.h-v1.4.16.2"
#include <libiptc/xtcshared.h>

#elif XTABLES_VERSION_CODE == 10
#include "xshared.h-v1.4.18"
#include <libiptc/xtcshared.h>

#elif XTABLES_VERSION_CODE == 11
#include "xshared.h-v1.6.0"
#include <libiptc/xtcshared.h>

#else
#error "The libxtables is newer than this package support and know of - Sorry!"
#error " Please inform the package author of this issue, thanks! "
#endif
