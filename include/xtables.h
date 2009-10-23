#ifndef _XTABLES_H
#define _XTABLES_H

#include <sys/types.h>
#include <linux/types.h>
#include <linux/netfilter/x_tables.h>
#include <libiptc/libxtc.h>
#include <stdbool.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif
#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE	136
#endif

/* Hawk: Trying to handle ABI segfault bug */

#define XTABLES_VERSION      IPTABLES_VERSION
#define XTABLES_VERSION_CODE IPTABLES_VERSION_CODE

#define XTABLES_API_VERSION(x,y,z)    (0x10000*(x) + 0x100*(y) + z)

#ifndef IPTABLES_VERSION_CODE
#error "IPTABLES version code not available"
#else
#define DETECTED_VERSION_CODE IPTABLES_VERSION_CODE
#endif

/* Include file for additions: new matches and targets. */
struct xtables_match
{
	struct xtables_match *next;

#if DETECTED_VERSION_CODE <= XTABLES_API_VERSION(1,4,1)
	xt_chainlabel name;
#elif DETECTED_VERSION_CODE == XTABLES_API_VERSION(1,4,2)
#warning "Trying to avoid segfaults on version 1.4.2"
	const char *name;
#else
#warning "Versions above 1.4.2 are unlikely to work due to ABI changes"
	const char *name;
#endif

	/* Revision of match (0 by default). */
	u_int8_t revision;

	u_int16_t family;

	const char *version;

	/* Size of match data. */
	size_t size;

	/* Size of match data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the match. */
	void (*init)(struct xt_entry_match *m);

	/* Function which parses command options; returns true if it
           ate an option */
	/* entry is struct ipt_entry for example */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const void *entry,
		     struct xt_entry_match **match);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the match iff non-NULL: put space at end */
	/* ip is struct ipt_ip * for example */
	void (*print)(const void *ip,
		      const struct xt_entry_match *match, int numeric);

	/* Saves the match info in parsable form to stdout. */
	/* ip is struct ipt_ip * for example */
	void (*save)(const void *ip, const struct xt_entry_match *match);

	/* Pointer to list of extra command-line options */
	const struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct xt_entry_match *m;
	unsigned int mflags;
#ifdef NO_SHARED_LIBS
	unsigned int loaded; /* simulate loading so options are merged properly */
#endif
};

struct xtables_target
{
	struct xtables_target *next;

#if DETECTED_VERSION_CODE <= XTABLES_API_VERSION(1,4,1)
	xt_chainlabel name;
#elif DETECTED_VERSION_CODE == XTABLES_API_VERSION(1,4,2)
	const char *name;
#else
	const char *name;
#endif

	/* Revision of target (0 by default). */
	u_int8_t revision;

	u_int16_t family;

	const char *version;

	/* Size of target data. */
	size_t size;

	/* Size of target data relevent for userspace comparison purposes */
	size_t userspacesize;

	/* Function which prints out usage message. */
	void (*help)(void);

	/* Initialize the target. */
	void (*init)(struct xt_entry_target *t);

	/* Function which parses command options; returns true if it
           ate an option */
	/* entry is struct ipt_entry for example */
	int (*parse)(int c, char **argv, int invert, unsigned int *flags,
		     const void *entry,
		     struct xt_entry_target **targetinfo);

	/* Final check; exit if not ok. */
	void (*final_check)(unsigned int flags);

	/* Prints out the target iff non-NULL: put space at end */
	void (*print)(const void *ip,
		      const struct xt_entry_target *target, int numeric);

	/* Saves the targinfo in parsable form to stdout. */
	void (*save)(const void *ip,
		     const struct xt_entry_target *target);

	/* Pointer to list of extra command-line options */
	const struct option *extra_opts;

	/* Ignore these men behind the curtain: */
	unsigned int option_offset;
	struct xt_entry_target *t;
	unsigned int tflags;
	unsigned int used;
#ifdef NO_SHARED_LIBS
	unsigned int loaded; /* simulate loading so options are merged properly */
#endif
};

/* Your shared library should call one of these. */
extern void xtables_register_match(struct xtables_match *me);
extern void xtables_register_target(struct xtables_target *me);

extern int string_to_number_ll(const char *s,
			       unsigned long long min,
			       unsigned long long max,
			       unsigned long long *ret);
extern int string_to_number_l(const char *s,
			      unsigned long min,
			      unsigned long max,
			      unsigned long *ret);
extern int string_to_number(const char *s,
			    unsigned int min,
			    unsigned int max,
			    unsigned int *ret);
extern bool strtonuml(const char *, char **, unsigned long *,
	unsigned long, unsigned long);
extern bool strtonum(const char *, char **, unsigned int *,
	unsigned int, unsigned int);
extern int service_to_port(const char *name, const char *proto);
extern u_int16_t parse_port(const char *port, const char *proto);
extern void
parse_interface(const char *arg, char *vianame, unsigned char *mask);

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM,
	RESOURCE_PROBLEM,
	P_ONLY_ONCE,
	P_NO_INVERT,
	P_BAD_VALUE,
	P_ONE_ACTION,
};

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64 u_int64_t __attribute__((aligned(8)))

int check_inverse(const char option[], int *invert, int *my_optind, int argc);
void exit_error(enum exittype, const char *, ...)__attribute__((noreturn,
							  format(printf,2,3)));
extern void param_act(unsigned int, const char *, ...);
extern const char *program_name, *program_version;

extern const char *ipaddr_to_numeric(const struct in_addr *);
extern const char *ipaddr_to_anyname(const struct in_addr *);
extern const char *ipmask_to_numeric(const struct in_addr *);
extern struct in_addr *numeric_to_ipaddr(const char *);
extern struct in_addr *numeric_to_ipmask(const char *);
extern void ipparse_hostnetworkmask(const char *, struct in_addr **,
	struct in_addr *, unsigned int *);

extern struct in6_addr *numeric_to_ip6addr(const char *);
extern const char *ip6addr_to_numeric(const struct in6_addr *);
extern const char *ip6addr_to_anyname(const struct in6_addr *);
extern const char *ip6mask_to_numeric(const struct in6_addr *);
extern void ip6parse_hostnetworkmask(const char *, struct in6_addr **,
	struct in6_addr *, unsigned int *);

/**
 * Print the specified value to standard output, quoting dangerous
 * characters if required.
 */
extern void save_string(const char *value);

#ifdef NO_SHARED_LIBS
#	ifdef _INIT
#		undef _init
#		define _init _INIT
#	endif
	extern void init_extensions(void);
#else
#	define _init __attribute__((constructor)) _INIT
#endif

/* Present in both iptables.c and ip6tables.c */
extern u_int16_t parse_protocol(const char *s);

#ifdef XTABLES_INTERNAL
#	include <xtables/internal.h>
#endif

#endif /* _XTABLES_H */
