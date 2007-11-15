#!/usr/bin/perl

use IPTables::libiptc;

BEGIN { $| = 1; print "1..2\n"; }
my $testiter = 1;

# TEST: init
my $table = IPTables::libiptc::init('filter');
unless ($table) {
    print STDERR "$!\n";
    print "not ok $testiter\n";
    exit(1);
}
#print "ok\n";
print "ok $testiter \n";
$testiter++;

my $chainname = "testchain1";
# TEST: create_chain
if(! $table->create_chain("$chainname")) {
 print "not ";
}
print "ok $testiter\n";
$testiter++;
