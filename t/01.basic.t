#!/usr/bin/perl
use lib 'lib/';
use strict;
use warnings;
use utf8;

use Test::More tests => 2;
use Test::Mojo;
use Mojolicious::Lite;
use Mojolicious::Plugin::BcryptPassword;
use Encode;

plugin BcryptPassword => { cost => 6 };

get '/' => sub {
    my $self = shift;
    $self->render( text => 'home page' );
};

my $password = 'bigtest';
my $bcrypted = app->hash_password($password);
ok( app->validate_password( $password, $bcrypted ), 'accept ok' );
ok( !app->validate_password( 'meow!', $bcrypted ), 'deny ok' );
