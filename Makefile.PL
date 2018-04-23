use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'Crypt::LE::Challenge::CoreNetworks',
    VERSION_FROM    => 'lib/Crypt/LE/Challenge/CoreNetworks.pm',
    LICENSE         => 'perl',
    PREREQ_PM       => {
                     'Digest::SHA' => 0,
                     'MIME::Base64' => '3.11',
                     'Net::DNS::CoreNetworks' => 0,
                   }
);
