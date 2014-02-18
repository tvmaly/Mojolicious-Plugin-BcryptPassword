use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Mojolicious::Plugin::BcryptPassword',
    AUTHOR              => 'Tyson Maly <tvmaly@cpan.org>',
    VERSION_FROM        => 'lib/Mojolicious/Plugin/BcryptPassword.pm',
    ABSTRACT_FROM       => 'lib/Mojolicious/Plugin/BcryptPassword.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Mojolicious-Plugin-BcryptPassword-*' },
);
