use 5.008004;
use ExtUtils::MakeMaker;

{
        package MY;

	sub post_initialize {
"
IPTABLES_VERSION:=1.3.4
LOCAL_LIB_IPTC:=-Llibrary_iptc/
"
        }

        sub postamble {
"
library_iptc/libiptc.a: library_iptc/*.c
	make -C library_iptc/ all IPTABLES_VERSION=\"\$(IPTABLES_VERSION)\"

iptables/iptables.o: iptables/*.c library_iptc/libiptc.a
	make -C iptables/ all PREFIX=\"\$(PREFIX)\" IPTABLES_VERSION=\"\$(IPTABLES_VERSION)\" IPT_LIB_DIR=\"\$(PREFIX)/lib/iptables\"


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
       AUTHOR         => 'Jesper Dangaard Brouer <jdb@comx.dk>') : ()),
    LIBS              => ['-liptc -ldl -lnsl'], # e.g., '-lm'
    LDDLFLAGS         => '-shared $(LOCAL_LIB_IPTC) -L$(PREFIX)/lib',
    LDFLAGS           => '-L$(PREFIX)/lib',
    DEFINE            => '-DIPTABLES_VERSION=\"$(IPTABLES_VERSION)\" -DIPT_LIB_DIR=\"$(PREFIX)/lib/iptables\"',
                         # e.g., '-DHAVE_SOMETHING'
    INC               => '-I. -I/usr/local/stow/include',
                         # e.g., '-I. -I/usr/include/other'
    # Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
    OBJECT            => '$(O_FILES) iptables/iptables.o',
                      # link all the C files too
    PREFIX            => '/usr/local/stow',
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
