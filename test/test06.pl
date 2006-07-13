#!/usr/bin/perl -w

use lib qw(../blib/lib);
use lib qw(../blib/arch);

use lib qw(blib/lib);
use lib qw(blib/arch);

#use ExtUtils::testlib;

use Data::Dumper;

use IPTables::libiptc;

print "start\n";

$table_name = 'filter';
my $table = IPTables::libiptc::init("$table_name");

if (not defined $table) {
    print "\$table is undef\n -=-=- STRERR: $!\n";
}


my $success;

#my $chainname = "FORWARD";
my $chainname = "INPUT";
if( $success = $table->builtin("$chainname")) {
    print "Chain is buildin: $chainname\n";
} else {
    print "Chain is NOT buildin: $chainname\n";
}

sub call_do_command($) {
    $array_ref = shift;
    print "do_command:\"" . "@$array_ref" . "\"\n";
    if( $success = $table->iptables_do_command($array_ref)) {
	print " *do_command ok: $success\n *ERR:$!\n\n";
    } else {
	print " *do_command failed: $success\n *ERR:$!\n\n";
    }
}

my @chain_list = $table->list_chains();

print "CHAINS:" . "@chain_list" . "\n";
foreach my $chain (@chain_list) {
    print "chain: \"$chain\"\n"
}

#my @dst_IPs = $table->list_rules_IPs("dst", "Access_601300004");
my @dst_IPs = $table->list_rules_IPs("src", "test");
print "dst_IPs:" . "@dst_IPs" . "\n";
foreach my $ip (@dst_IPs) {
    print "ip: $ip \n"
}

#@arguments = ("-t", "filter", "-A", "INPUT");
#@arguments = ("-A", "INPUT", "-s", "1.2.3.4");
#@arguments = ("-N", "test");
#@arguments = ("badehat", "-N test");
#@arguments = ("badehat", "-N", "test");

@arguments = ("-nL", "test");
#call_do_command(\@arguments);

open(MYFILE, ">> /tmp/test06");

#open(STDOUT, ">&MYFILE");
#open(STDOUT, "|-");
my $hat = eval { call_do_command(\@arguments)};
#while(<STDIN>) {
#    print "$.: $_";
#}

#close(STDOUT);

#@arguments = ("-A test", "-p", "tcp");
#@arguments = ("-I", "test", "-s", "4.3.2.1");
@arguments = ("-I", "test", "-s", "4.3.2.1", "-j", "ACCEPT");
#@arguments = ("-t", "filter", "-N test");
#@arguments = ("-h");
#@arguments = ("--help");
#@arguments = ["--help", "-m tcp"];
print Dumper(\@arguments);

close(MYFILE);

print $table->{'tablename'} . "\n";

if( $table->commit()) {
    print "Commit OK\n";
} else {
    print "Commit FAILED\n";
}
