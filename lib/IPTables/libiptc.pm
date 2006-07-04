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

our $VERSION = '0.01';

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
  blah blah blah

=head1 DESCRIPTION

Stub documentation for IPTables::libiptc, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.


=head1 METHODS

=head2 Chain Operations

=over

=item $success = $table-E<gt>set_policy('chainname', 'target')

=item $success = $table-E<gt>set_policy('chainname', 'target', 'pkt_cnt', 'byte_cnt')

=item ($success, $old_policy, $old_pkt_cnt, $old_pkt_cnt) = 
      $table-E<gt>set_policy('chainname', 'target')

Sets the default policy.  C<set_policy> can be called severaly ways.
Upon success full setting of the policy the old policy and counters
are returned.  The counter setting values are optional.

=head2 EXPORT

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

Jesper Dangaard Brouer, E<lt>jdb@comx.dkE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Jesper Dangaard Brouer

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
