package IPTables::libiptc;

use 5.008004;
use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;

# Our libiptc.so is loaded dynamically, and other dynamic libraries
# need some of the external symbols defined in the library.  Thus,
# when loading the library the RTLD_GLOBAL flag needs to be set, as it
# will make symbol resolution available of subsequently loaded
# libraries.
#
# This solves the error:
#  Couldn't load target `standard':
#   libipt_standard.so: undefined symbol: register_target
#
# This flag 0x01 equals RTLD_GLOBAL.
sub dl_load_flags {0x01}

use AutoLoader;

our @ISA = qw(Exporter DynaLoader);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use IPTables::libiptc ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	IPT_MIN_ALIGN
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	IPT_MIN_ALIGN
);

our $VERSION = '0.02';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&IPTables::libiptc::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('IPTables::libiptc', $VERSION);

#bootstrap IPTables::libiptc $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

IPTables::libiptc - Perl extension for iptables libiptc

=head1 SYNOPSIS

  use IPTables::libiptc;

  $table = IPTables::libiptc::init('filter');

  $table->create_chain("badehat");

  # Its important to commit/push-back the changes to the kernel
  $table->commit();

=head1 DESCRIPTION

This package provides a perl interface to the netfilter/iptables
C-code and library C<libiptc>.

This package is written from scratch, but is inspired by the CPAN
module IPTables-IPv4.  The CPAN module IPTables-IPv4 could not be used
because it has not been keept up-to-date, with the newest iptables
extentions.  This is a result of the module design, as it contains
every extention and thus needs to port them individually.

This package has another approach, it links with the systems libiptc.a
library and depend on dynamic loading of iptables extensions available
on the system.

The module only exports the libiptc chain manipulation functions.  All
rule manipulations are done through the iptables.c C<do_command>
function.  As iptables.c is not made as a library, the package
unfortunally needs to maintain/contain this C file.

=head2 Iptables kernel to userspace design

=over

The reasoning behind making this module comes from how
iptables/libiptc communicate with the kernel.  Iptables/libiptc
transfers the entire ruleset from kernel to userspace, and back again
after making some changes to the ruleset.

This is a fairly large operation if only changing a single rule.  That
is actually the behavior of the iptables command.

Thus, with this knowledge it make sense to make several changes before
commit'ing the changes (entire ruleset) back to the kernel.  This is
the behavior/purpose of this perl module.


=head1 METHODS

=head2 Chain Operations

=over

=item B<set_policy>

    $success = $table->set_policy('chainname', 'target');
    $success = $table->set_policy('chainname', 'target', 'pkt_cnt', 'byte_cnt');
    ($success, $old_policy, $old_pkt_cnt, $old_pkt_cnt) = $table->set_policy('chainname', 'target');

Sets the default policy.  C<set_policy> can be called severaly ways.
Upon success full setting of the policy the old policy and counters
are returned.  The counter setting values are optional.


=head2 Rules Operations

No rules manipulation functions is mapped/export from libiptc, instead
the iptables C<do_command> function is exported to this purpose.


=head2 Listing Operations

=item B<list_chains>

    @array            = $table->list_chains();
    $number_of_chains = $table->list_chains();

Lists all chains.  Returns the number of chains in SCALAR context.

=item B<list_rules_IPs>

    @array           = $table->list_rules_IPs('type', 'chainname');
    $number_of_rules = $table->list_rules_IPs('type', 'chainname');

This function lists the (rules) source or destination IPs from a given
chain.  The C<type> is either C<src> or C<dst> for source and
destination IPs.  The netmask is also listed together with the IPs,
but seperated by a C</> character.  If chainname does not exist
C<undef> is returned.

=head2 Iptables commands (from iptables.h)

=item B<iptables_do_command>

    $table->iptables_do_command(\@array_ref)

Example of an array which contains a command:

    my @array = ("-I", "test", "-s", "4.3.2.1", "-j", "ACCEPT");
    $table->iptables_do_command(\@array);


=head1 EXPORT

None by default.

=head2 Exportable constants

  IPT_MIN_ALIGN



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Jesper Dangaard Brouer, E<lt>hawk@comx.dkE<gt> or E<lt>hawk@diku.dkE<gt>.

=head2 Authors SVN version information

 $LastChangedDate$
 $Revision$
 $LastChangedBy$


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Jesper Dangaard Brouer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
