#!/usr/bin/perl

use IPTables::libiptc;

BEGIN { $| = 1; print "1..2\n"; }
my $testiter = 1;

# TEST: init
my $table = IPTables::libiptc::init('filter');
unless ($table) {
        print "not ok 1\n";
        exit(1);
}
#print "ok\n";
print "ok $testiter \n";
$testiter++;


# TEST: is_chain
if(! $table->is_chain("FORWARD")) {
 print "not ";
}
print "ok $testiter\n";
$testiter++;
