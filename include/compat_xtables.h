#ifndef _COMPAT_XTABLES_H
#define _COMPAT_XTABLES_H

/*
 * Tricks to keep compatible with xtables libs and changing iptables
 * versions and iptables.c
 *
 * Author: Jesper Dangaard Brouer <hawk@comx.dk>
 */

#include <xtables.h>


/* ABI change: for xtables_check_inverse()

 * iptables  :  v1.4.4 -> 1.4.5
 * xtables.so:  3 -> 4
 * commit    :  bf97128c  (libxtables: hand argv to xtables_check_inverse)

OLD:
int xtables_check_inverse(const char option[], int *invert,
			  int *my_optind, int argc);

NEW:
int xtables_check_inverse(const char option[], int *invert,
			  int *my_optind, int argc, char **argv);

*/
int compat_xtables_check_inverse(const char option[], int *invert,
				 int *my_optind, int argc, char **argv)
{
#if XTABLES_VERSION_CODE >= 4
	xtables_check_inverse(option, invert, my_optind, argc, argv);
#else
	xtables_check_inverse(option, invert, my_optind, argc);
#endif
}



#endif
