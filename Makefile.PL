use 5.008004;
use ExtUtils::MakeMaker;

{
        package MY;

	sub exec_iptables($) {
	    my $cmd = shift;
	    my $exitcode;
	    print "Detect iptables version via command: \"$cmd\"\n";

	    my $output = `$cmd 2>&1`;
	    if ($? == -1) {
		# Cannot execute the command
		print(" WARN: Cannot execute the command:$cmd (err:$!)\n");
		$exitcode=-1;
	    } else {
		# The exit code is in the high byte of the 16-bit status word
		$exitcode = $? >> 8;
	    }
	    return ($exitcode, $output);
	}

	sub detect_iptables_version($) {
	    my $default_version = shift;
	    my $ver = $default_version;
	    my $cmd = "iptables -V";
	    my $xtables_libdir = "/lib/xtables";
	    my $exitcode;

	    ($exitcode, $output) = exec_iptables("iptables -V");
	    if ($exitcode == -1) {
		($exitcode, $output) = exec_iptables("/usr/local/sbin/iptables -V");
		if ($exitcode != -1) {
		    $xtables_libdir = "/usr/local/libexec/xtables";
		}
	    }
	    ($exitcode, $output) = exec_iptables("/sbin/iptables -V")
		if ($exitcode == -1);

	    if ($exitcode>0) {
		print STDERR ("WARN: Err running command:\"$cmd\" (err:$!)\n");
		print STDERR ("WARN: Cannot auto-detect iptables version\n");
	    } else {
		chomp $output;
		#print "Matching on output:[$output]\n";
		if ($output =~ /iptables v(\d+)\.(\d+)\.(\d+)/) {
		    my $major    = $1;
		    my $minor    = $2;
		    my $revision = $3;
		    $ver="$major.$minor.$revision";
		    print "Detected iptables version: $major.$minor.$revision\n";
		    if ($major > 1) {
			print "Too high major version, fallback\n";
			$ver = $default_version;
		    }

		    if ($minor > 4) {
			print "Module only supports version 1.4.x, fallback\n";
			$ver = $default_version
		    }

		    if ($minor < 4) {
			print "Version below 1.4.x, good luck\n";
		    }

		    if ($minor == 4 && $revision != 1) {
			print "\n";
			print "-=-=-=- WARNING of segfaults!!! -=-=-=-\n";
			print "\n";
			print " This perl module release only supports iptables\n";
			print "  version ${default_version}\n";
			print "\n";
			print " There are some segfault issues when comparing the IPTABLES_VERSION\n";
			print " variable (in the dynamic loadable modules) between iptables versions\n";
			print " 1.4.1 and 1.4.2, and also between 1.4.2 and 1.4.3. It has been fixed\n";
			print " from version 1.4.3.2 and beyond (see git commit c4edfa63eda06)\n";
			print "\n";
			print " If your system provides the correct xtables.h header file, there is\n";
			print " a good chance it will work anyhow.  You have been warned!\n";
			print "\n";
		    }

		}
	    }
	    print("Using iptables version: $ver\n");
	    return ($ver, $xtables_libdir);
	}

	sub post_initialize {
	    my $default_version = "1.4.1";
	    my ($ver, $xtables_libdir) = detect_iptables_version($default_version);

"
IPTABLES_VERSION:=$ver
XTABLES_LIBDIR:=$xtables_libdir
LOCAL_LIB_IPTC:=-Llibrary_iptc/
"
        }

        sub postamble {
"
library_iptc/libiptc.a: library_iptc/*.c
	make -C library_iptc/ all IPTABLES_VERSION=\"\$(IPTABLES_VERSION)\"

iptables/iptables.o iptables/xtables.o: iptables/*.c library_iptc/libiptc.a
	make -C iptables/ all PREFIX=\"\$(PREFIX)\" IPTABLES_VERSION=\"\$(IPTABLES_VERSION)\" XTABLES_LIBDIR=\"\$(XTABLES_LIBDIR)\"

install::
	make -C iptables/ install

clean::
	make -C iptables/ clean
	make -C library_iptc/ clean
";
        }
}


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'IPTables::libiptc',
    VERSION_FROM      => 'lib/IPTables/libiptc.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/IPTables/libiptc.pm', # retrieve abstract from module
       AUTHOR         => 'Jesper Dangaard Brouer <hawk@comx.dk>') : ()),
    LIBS              => ['-ldl -lnsl'], # e.g., '-lm'
#   LIBS              => ['-Llibrary_iptc/ -liptc -ldl -lnsl'], # e.g., '-lm'
    LDDLFLAGS         => '-shared $(LOCAL_LIB_IPTC) -L$(PREFIX)/lib',
    LDFLAGS           => '-L$(PREFIX)/lib',
    DEFINE            => '-g -DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -DXTABLES_LIBDIR=\"\$(XTABLES_LIBDIR)\"',
                         # e.g., '-DHAVE_SOMETHING'
    INC               => '-I/usr/local/include -I./include -I.',
                         # e.g., '-I. -I/usr/include/other'
    # Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
    OBJECT            => '$(O_FILES) iptables/iptables.o iptables/xtables.o library_iptc/libiptc.a',
                      # link all the C files too
    PREFIX            => '/usr/local',
    TYPEMAPS          => ['libiptc.typemap'],
#   depend             => { 'iptables/iptables.o' => 'library_iptc/libiptc.a'}
#   depend             => { 'iptables/iptables.o' => 'library_iptc/libiptc.a'}
);
if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw(IPT_MIN_ALIGN));
  ExtUtils::Constant::WriteConstants(
                                     NAME         => 'IPTables::libiptc',
                                     NAMES        => \@names,
                                     DEFAULT_TYPE => 'IV',
                                     C_FILE       => 'const-c.inc',
                                     XS_FILE      => 'const-xs.inc',
                                  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
