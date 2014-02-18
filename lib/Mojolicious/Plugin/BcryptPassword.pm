package Mojolicious::Plugin::BcryptPassword;

use warnings;
use strict;
use Carp;

use version; 

our $VERSION = qv('1.0.0');

use Mojo::Base 'Mojolicious::Plugin';
use Crypt::Random;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);

sub register {
    my ($self, $app, $args) = @_;
    $args ||= {};


    $app->helper(
        hash_password => sub {

            my $otherself = shift;
            
            my ( $plain_password, $settings ) = @_;
            unless ( defined $settings && $settings =~ /^\$2a\$/ ) {
                my $cost = sprintf('%02d', $args->{cost} || 6);
                $settings = join( '$', '$2a', $cost, generate_salt() );
            }
            return bcrypt( $plain_password, $settings );            

        }
    );

    $app->helper(
        validate_password => sub {

            my $otherself = shift;

            my ($plain_password, $hashed_password) = @_;

            if ($hashed_password =~ m!^(\$2a\$\d{2}\$[A-Za-z0-9+\\.\/]{22})!) {
 
            # Use a letter by letter match 
            # rather than a complete string match to avoid timing attacks
                my $match = $otherself->hash_password($plain_password, $1);
                my $bad = 0;
                for (my $n=0; $n < length $match; $n++) {
                    $bad++ if substr($match, $n, 1) ne substr($hashed_password, $n, 1);
                }
 
                return $bad == 0;
            } else {
                return 0;
            }

        }
    );
}


sub generate_salt {
    return Crypt::Eksblowfish::Bcrypt::en_base64(Crypt::Random::makerandom_octet(Length=>16));
}

1; # Magic true value required at end of module
__END__

=head1 NAME

Mojolicious::Plugin::BcryptPassword - bcrypt your passwords and validate against a bcrypt hashed password


=head1 VERSION

This document describes Mojolicious::Plugin::BcryptPassword version 1.0.0


=head1 SYNOPSIS

    use Mojolicious::Plugin::BcryptPassword;
  
    plugin BcryptPassword => { cost => 6 };

    my $encrypted_password = app->hash_password('secret');

    my $is_correct_password = app->validate_password('secret',$encrypted_password);
  
=head1 DESCRIPTION

    bcrypt provides a more computationaly costly calculation than md5 hashing, so it is less likely that 
    your passwords will fall into the wrong hands if your database is breached.  

    I borrowed some of the code from Mojolicious::Plugin::Bcrypt but I did not like
    the method used for the salt generation.  I also did not like the validation method. 
    I prefered the methods listed in this gist https://gist.github.com/gcrawshaw/1071698


=head1 INTERFACE 

=over

=item app->hash_password takes a plain text password and optional bcrypt settings otherwise it uses a default cost of 6 and generates a random salt value

=item app->validate_password takes a plain text password and the hashed password to validate against.  returns true if plain text password hashes to hashed password otherwise fales.  The hashed password has the settings, cost, and salt as a prefix

=back

=head1 CONFIGURATION AND ENVIRONMENT

Mojolicious::Plugin::BcryptPassword requires no configuration files or environment variables.


=head1 DEPENDENCIES

Mojolicious
Crypt::Random
Crypt::Eksblowfish::Bcrypt

=head1 INCOMPATIBILITIES

None reported.


=head1 BUGS AND LIMITATIONS

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-mojolicious-plugin-bcryptpassword@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Tyson Maly  C<< <tvmaly@cpan.org> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2014, Tyson Maly C<< <tvmaly@cpan.org> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
