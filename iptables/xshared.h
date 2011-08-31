#include <xtables.h>

#if   XTABLES_VERSION_CODE < 7
#include "xshared.h-old"

#elif XTABLES_VERSION_CODE == 7
#include "xshared.h-v1.4.12"

#else
#error "The libxtables is newer than this package support and know of - Sorry!"
#error " Please inform the package author of this issue, thanks! "
#endif
