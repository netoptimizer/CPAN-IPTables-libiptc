#include <xtables.h>

#if   XTABLES_VERSION_CODE < 7
#include "xshared.c-old"

#elif XTABLES_VERSION_CODE == 7
#include "xshared.c-v1.4.12"

#elif XTABLES_VERSION_CODE == 9
#include "xshared.c-v1.4.16.2"

#elif XTABLES_VERSION_CODE == 10
#include "xshared.c-v1.4.18"

#elif XTABLES_VERSION_CODE == 11
#include "xshared.c-v1.6.0"

#elif XTABLES_VERSION_CODE == 12
#include "xshared.c-v1.6.1"

#else
#error "The libxtables is newer than this package support and know of - Sorry!"
#error " Please inform the package author of this issue, thanks! "
#endif
