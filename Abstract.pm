package Maypole::Plugin::Authentication::Abstract;

use strict;
use Apache::Cookie;
use Storable qw(freeze thaw);
use URI;

our $VERSION = '0.10';

Maypole->mk_accessors(qw(user session session_id));
Maypole::Config->mk_accessors(qw(auth login_exception session_exception));

=head1 NAME

Maypole::Plugin::Authentication::Abstract - Abstract Authentication for Maypole

=head1 SYNOPSIS

Simple example of all three security levels:

    use Maypole::Application qw(Authentication::Abstract);

    sub authenticate {
        my $r = shift;
        if ( $r->table eq 'openforall' ) {
            $r->public;
        }
        elsif ( $r->table eq 'membersonly' ) {
            $r->private;
            $r->template('login') unless $r->user;
        }
        elsif ( $r->table eq 'topsecret' ) {
            $r->restricted;
            $r->template('login') unless $r->user;
        }
        return OK;
    }

    [% session %]
    [% session_id %]
    [% ticket %]

Another example:

    use Maypole::Application qw(Authentication::Abstract);

    MyApp->config->auth(
        user_class    => 'MyApp::Customer',
        user_field    => 'email',
        session_class => 'Apache::Session::Postgres',
        session_args  => {
            DataSource => 'dbi:Pg:dbname=myapp',
            UserName   => 'postgres',
            Password   => '',
            Commit     => 1
        }
    );

    sub authenticate {
        my $r = shift;
        if ( $r->table eq 'products' && $r->action eq 'list' ) {
            $r->public;
        }
        elsif ( $r->table eq 'products' && $r->action eq 'search' ) {
            $r->private;
            $r->template('login') unless $r->user;
        }
        elsif ( $r->table eq 'products' && $r->action eq 'edit' ) {
            $r->restricted;
            $r->template('login') unless $r->user;
        }
        return OK;
    }

With exceptions:

    use Maypole::Application qw(Authentication::Abstract);
    use Exception::Class
      LoginException   => { description => 'Login failed' },
      SessionException => { description => 'Session initialization failed' };

    MyApp->config->login_exception('LoginException');
    MyApp->config->session_exception('SessionException');

    sub authenticate {
        my $r = shift;
        if ( $r->table eq 'openforall' ) {
            $r->public;
            return OK;
        }
        elsif ( $r->table eq 'membersonly' ) {
            $r->private;
            $r->template('login') unless $r->user;
            return OK;
        }
        elsif ( $r->table eq 'topsecret' ) {
            $r->restricted;
            $r->template('login') unless $r->user;
            return OK;
        }
        return DECLINED;
    }

    sub exception {
        my ( $r, $e ) = @_;
        if ( $e->isa('LoginException') ) {
            warn "Login failed: $e";
            # Do something to correct the failure
            return OK;
        }
        elsif ( $e->isa('SessionException') ) {
            warn "Session initialization failed: $e";
            # Do something to correct the failure
            return OK;
        }
        return ERROR;
    }

Tickets in templates

    <INPUT TYPE="hidden" NAME="ticket" VALUE="[% ticket %]">

Global session handling is also possible:

    sub authenticate {
        my $r = shift;
        $r->public;
        if ( $r->table eq 'products' && $r->action eq 'search' ) {
            $r->private;
            $r->template('login') unless $r->user;
        }
        elsif ( $r->table eq 'products' && $r->action eq 'edit' ) {
            $r->restricted;
            $r->template('login') unless $r->user;
        }
        return OK;
    }

=head1 DESCRIPTION

This module is based on Maypole::Authentication::UserSessionCookie but adds
some more advanced features.

Note that you need Maypole 2.0 or newer to use this module.

For example we have three levels of security:

        Public: No authentication, only session management
       Private: Authenticate once, go everywhere
    Restricted: Authenticate and reauthorize with a ticket for every
                request (best used in a post form as hidden input)

The configuration works similar to Maypole::Authentication::UserSessionCookie
but with some little additions.

    $r->{session_id} can be used from parse_path() for example,
    useful if the user has cookies disabled.

We provide a number of methods to be inherited by a Maypole class.
The three methods C<public>, C<private> and C<restricted> determine the security
level.

=head2 public

    $r->public;

C<public> checks for a session cookie and looks into the C<session_id> slot
of the Maypole request and then populates the resulting session hash to the
C<session> slot.

=cut

sub public { shift->login }

=head2 private

    $r->private;

C<private> does the same as public but also calls C<check_credentials> if you
haven't authorized before.
If the login was successful it populates a C<User> object to the C<user> slot of
the Maypole object.

=cut

sub private {
    my $r = shift;
    $r->public;
    my ( $uid, $user );
    unless ( $r->{session}->{uid} ) {
        ( $uid, $r->{user} ) = $r->check_credentials;
        return 0 unless $uid;
    }
    $r->{session}->{uid} ||= $uid;
    $r->user( $r->uid_to_user( $r->{session}->{uid} ) );
}

=head2 restricted

    $r->restricted;

C<restricted> does the same as C<private> but also calls C<ticket>.

=cut

sub restricted {
    my $r = shift;
    $r->public;
    $r->ticket;
}

=head2 login

This method creates the session hash.
It also sets C<$r->{template_args}{session}> and
C<$r->{template_args}{session_id}>.

=cut

sub login {
    my $r = shift;
    return 1 if $r->session;    # We already have a session
    my %jar               = Apache::Cookie->new( $r->ar )->parse;
    my $cookie_name       = $r->config->{auth}->{cookie_name} || "sessionid";
    my $cookie_session_id = $jar{$cookie_name}->value
      if ( exists $jar{$cookie_name} );
    my $session_id = $r->session_id || undef;
    my $session_class = $r->config->{auth}->{session_class}
      || 'Apache::Session::File';
    my $session_args = $r->config->{auth}->{session_args}
      || {
        Directory     => '/tmp/sessions',
        LockDirectory => '/tmp/sessionlock',
      };
    eval {
        $session_class->require;
        tie %{ $r->{session} }, $session_class,
          ( $cookie_session_id || $session_id ), $session_args;
    };
    if ( my $err = $@ ) {
        $r->_logout_cookie;
        if ( my $e = $r->config->session_exception ) {
            $e->throw( error => $err );
        }
        return 0;
    }
    $r->session_id( $r->{session}->{_session_id} );
    $r->{template_args}->{session_id} = $r->{session_id};
    $r->{template_args}->{session}    = $r->{session};
    $r->_login_cookie
      if ( ( !$session_id && !$cookie_session_id )
        || $session_id ne $cookie_session_id );
    return 1;
}

=head2 logout

This method deletes the session hash.

=cut

sub logout {
    my $r = shift;
    $r->user(undef);
    tied( %{ $r->{session} } )->delete;
    $r->_logout_cookie;
}

=head2 check_credentials

This method checks for two form parameters (typically C<user> and C<password>
but configurable) and does a C<search> on the user class for those values.
If the credentials are wrong, then C<$r->{template_args}{login_error}> is set to
an error string.

=cut

sub check_credentials {
    my ( $r, $user, $password ) = @_;
    my $user_class = $r->config->{auth}->{user_class}
      || ( ( ref $r ) . '::User' );
    $user_class->require;
    my $user_field     = $r->config->{auth}->{user_field}     || 'user';
    my $password_field = $r->config->{auth}->{password_field} || 'password';
    unless ( $user && $password ) {
        $user     = $r->{params}->{$user_field};
        $password = $r->{params}->{$password_field};
        return 0 unless ( $user && $password );
    }
    my @users = $user_class->search(
        $user_field     => $user,
        $password_field => $password
    );
    if ( !@users ) {
        $r->{template_args}->{login_error} = 'Bad username or password';
        if ( my $e = $r->config->login_exception ) {
            $e->throw( error => $r->{template_args}->{login_error} );
        }
        return 0;
    }
    return ( $users[0]->id, $users[0], $user, $password );
}

=head2 uid_to_user

This method returns the result of a C<retrieve> on the UID from the user class.

=cut

sub uid_to_user {
    my $r          = shift;
    my $user_class = $r->config->{auth}->{user_class}
      || ( ( ref $r ) . "::User" );
    $user_class->require;
    $user_class->retrieve(shift);
}

=head2 ticket

This method checks for a form parameter, C<ticket> and reauthorizes the user
whenever it is called.
By default the ticket is just a serialized array represented as hex string
containing the user and the password, but it is very simple to overload
C<ticket> with a better method. Use a Crypt:: module or even Kerberos!
It also sets $r->{template_args}{ticket}.

=cut

sub ticket {
    my $r = shift;
    if ( my $ticket = $r->{params}->{ticket} ) {
        my ( $user, $password );
        eval {
            ( $user, $password ) = @{ thaw pack 'H*', $r->{params}->{ticket} };
        };
        if ( my $err = $@ ) {
            $r->{template_args}->{login_error} = 'Invalid ticket';
            if ( my $e = $r->config->login_exception ) {
                $e->throw( error => $err );
            }
            return 0;
        }
        my $uid;
        ( $uid, $r->{user} ) = $r->check_credentials( $user, $password );
        return 0 unless $uid;
        $r->{session}->{uid} ||= $uid;
        $r->{template_args}->{ticket} = $r->{params}{ticket};
    }
    else {
        my ( $uid, $user, $password );
        ( $uid, $r->{user}, $user, $password ) = $r->check_credentials;
        return 0 unless $uid;
        $r->{template_args}->{ticket} = unpack 'H*',
          freeze [ $user, $password ];
    }
    return 1;
}

sub _login_cookie {
    my $r           = shift;
    my $cookie_name = $r->config->{auth}->{cookie_name} || "sessionid";
    my $cookie      = Apache::Cookie->new(
        $r->{ar},
        -name    => $cookie_name,
        -value   => $r->session_id,
        -expires => $r->config->{auth}->{cookie_expiry} || '',
        -path    => URI->new( $r->config->uri_base )->path
    );
    $cookie->bake;
}

sub _logout_cookie {
    my $r           = shift;
    my $cookie_name = $r->config->{auth}->{cookie_name} || "sessionid";
    my $cookie      = Apache::Cookie->new(
        $r->{ar},
        -name    => $cookie_name,
        -value   => undef,
        -path    => URI->new( $r->config->uri_base )->path,
        -expires => "-10m"
    );
    $cookie->bake;
}

=head1 TODO

Better documentation.

=head1 AUTHOR

Sebastian Riedel, C<sri@cpan.org>

=head1 COPYRIGHT

Copyright 2004 Sebastian Riedel. All rights reserved.

This program is free software, you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
