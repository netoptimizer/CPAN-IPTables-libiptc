
#include <xtables.h>

#if   XTABLES_VERSION_CODE == 1
#warning "This version of xtables is not recommended"
#warning " please upgrade to at least v1.4.3.2"
#include "iptables.c-v1.4.4"

#elif XTABLES_VERSION_CODE == 2
#include "iptables.c-v1.4.4"

#elif XTABLES_VERSION_CODE == 3
#include "iptables.c-v1.4.5"

#elif XTABLES_VERSION_CODE == 4
#include "iptables.c-v1.4.8"

#elif XTABLES_VERSION_CODE == 5
#include "iptables.c-v1.4.10"

#elif XTABLES_VERSION_CODE == 6
#include "iptables.c-v1.4.11.1"

#elif XTABLES_VERSION_CODE > 6
#error "The libxtables is newer than this package support and know of - Sorry!"
#error " Please inform the package author of this issue, thanks! "

#endif /* XTABLES_VERSION_CODE */
