#!/usr/bin/perl -w

use lib qw(../blib/lib);
use lib qw(../blib/arch);

use lib qw(blib/lib);
use lib qw(blib/arch);

#use ExtUtils::testlib;

use Data::Dumper;

use IPTables::libiptc;

$table_name = 'filter';
my $table = IPTables::libiptc::init("$table_name");

print "errno $! \n";


my $success;

my $chain = "badehat";
my @insert_rule     = ("-I", "FORWARD", "!", "-s", "!", "4.3.2.1", "-j", "$chain");
#my @delete_rule     = ("-D", "FORWARD", "-s", "4.3.2.1", "-j", "$chain");
my @delete_rule     = ("-D", "FORWARD", "-s", "4.3.2.1", "-j", "$chain");
#my @delete_rule_num = ("-D", "FORWARD", "1");

$success = $table->create_chain($chain);
if (!$success) {
    print "Cannot create chain: $chain\n";
}

$success = $table->iptables_do_command(\@insert_rule);
if (!$success) {
    print "errno(0) [$!] \n";
}

my $refs = $table->get_references("$chain");
print "Chain: $chain has $refs references.\n";

$success = $table->iptables_do_command(\@delete_rule);
if (!$success) {
    print "errno(1) [$!] \n";
}
print "errno(1.1) [$!] \n";


#$success = $table->iptables_do_command(\@delete_rule_num);
$refs = $table->get_references("$chain");
print "Chain: $chain has $refs references.\n";

#eval {
#    local $SIG{'__DIE__'};
    if( !($table->delete_chain("$chain"))) {
	print "Error could not delete chain: $chain\n";
	print "Error string: $!\n";
    }
#};

#if ($@) {
    print "errno(2) [$!] \n";
#} else {
#    print "ingen eval fejl [$!]\n";
#}


if( $table->commit()) {
    print "Commit OK\n";
} else {
    print "Commit FAILED\n";
}
