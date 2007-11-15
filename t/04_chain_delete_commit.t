#!/usr/bin/perl

use IPTables::libiptc;

BEGIN { $| = 1; print "1..3\n"; }
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
if(! $table->delete_chain("$chainname")) {
 print STDERR "$!\n";
 print "not ";
}
print "ok $testiter\n";
$testiter++;

# TEST: commit
if(! $table->commit()) {
 print "not ";
}
print "ok $testiter\n";
$testiter++;
