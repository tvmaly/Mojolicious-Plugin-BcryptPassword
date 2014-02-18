#!/usr/bin/perl
use lib 'lib/';
use strict;
use warnings;
use utf8;

use Test::More tests => 5;
use Test::Mojo;
use Mojolicious::Lite;
use Mojolicious::Plugin::BcryptPassword;
use Encode;

plugin BcryptPassword => { cost => 6 };

get '/hashpassword' => sub {
    my $self = shift;
    my ( $p, $s ) = map { $self->param($_) } qw/p s/;
    $self->render( text => $self->hash_password( $p, $s ) );
};

get '/validatepassword' => sub {
    my $self = shift;
    my ( $p, $c ) = map { $self->param($_) } qw/p c/;
    my $ok = $self->validate_password( $p, $c );
    $self->render( text => ($ok ? 'Pass' : 'Fail') );
};

my $t = Test::Mojo->new();
my @A = <DATA>;

for (@A) {
    chomp;
    s/([^ ]+) ([^ ]+) *//;
    my ( $settings, $hash ) = ( $1, $2 );
    my $encoded = encode("utf-8", $_);
    $t->get_ok("/hashpassword?p=$encoded&s=$settings")->content_is( $settings . $hash );
    $t->get_ok( "/validatepassword?p=$encoded&c=" . $settings . $hash, encode("utf-8", $_) );
}

my $password = 'big secret';
my $bcrypted = app->hash_password($password);
ok( app->validate_password( $password, $bcrypted ), 'accept ok' );
ok( !app->validate_password( 'meow!', $bcrypted ), 'deny ok' );

__DATA__
$2a$06$ESNl9eFdZ9EJczuFnghFNe Uq7fLKO6Pii6BEFz7qVAXRefJAYQIqy bigtest
