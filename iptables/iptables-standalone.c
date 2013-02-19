#include <xtables.h>

#if   XTABLES_VERSION_CODE < 7
#include "iptables-standalone.c-old"

#elif XTABLES_VERSION_CODE == 7
#include "iptables-standalone.c-v1.4.12"

#elif XTABLES_VERSION_CODE == 9
#include "iptables-standalone.c-v1.4.16.2"

#else
#error "The libxtables is newer than this package support and know of - Sorry!"
#error " Please inform the package author of this issue, thanks! "
#endif
