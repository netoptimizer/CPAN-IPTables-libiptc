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
# TEST: is_chain
if(! $table->is_chain("$chainname")) {
 print STDERR "$!\n";
 print "not ";
}
print "ok $testiter\n";
$testiter++;
