package Crypt::LE::Challenge::CoreNetworks;

use strict;
use warnings;

our $VERSION = '0.002';

use Digest::SHA 'sha256';
use MIME::Base64 'encode_base64url';
use Net::DNS::CoreNetworks;


sub new {
    my $class = shift;
    my $self = bless {}, $class;
    $self->{client} = Net::DNS::CoreNetworks->new();
    return $self;
}

sub handle_challenge_http {
    return 0;
}

sub handle_challenge_tls {
    return 0;
}

sub handle_challenge_dns {
    my $self = shift;
    my ($challenge, $params) = @_;
    $challenge->{logger}->info("Processing the 'dns' challenge for '$challenge->{domain}' with " . __PACKAGE__) if $challenge->{logger};
    my $data = encode_base64url(sha256("$challenge->{token}.$challenge->{fingerprint}"));
    my (undef, $domain) = $challenge->{domain} =~ /^(\*\.)?(.+)$/;
    my $fqdn = '_acme-challenge.' . $domain;

    if ($self->{client}->login($ENV{CORENETWORKS_USER}, $ENV{CORENETWORKS_PASSWORD})) {
        # find zone
        my @zones = map $_->{name}, grep $_->{type} eq "master", $self->{client}->zones();

        foreach my $zonename (_lsort(@zones)) {
            if ($fqdn =~ /^(.*)\.\Q$zonename\E$/) {
                my $rr = $1;
                my $zone = $self->{client}->zone($zonename);

                # create record
                $challenge->{logger}->info("Creating $rr TXT record ($data) in zone $zonename") if $challenge->{logger};
                if ($zone->add($rr, 60, 'TXT', $data)) {
                    $self->{cleanup}->{$challenge->{domain}}->{zone} = $zonename;
                    $self->{cleanup}->{$challenge->{domain}}->{rr} = $rr;
                    $self->{cleanup}->{$challenge->{domain}}->{data} = $data;
                    if ($zone->commit()) {
                        sleep(5);
                        return 1;
                    }
                }

                last;
            }
        }

    }
    else {
        $challenge->{logger}->error("Unable to log into CoreNetworks DNS API. Have yo set the ENV vars CORENETWORKS_USER and CORENETWORKS_PASSWORD corectly?") if $challenge->{logger};
        return 0;
    }
}

sub handle_verification_http {
    return 0;
}

sub handle_verification_tls {
    return 0;
}

sub handle_verification_dns {
    my $self = shift;
    my ($results, $params) = @_;
    $results->{logger}->info("Processing the 'dns' verification for '$results->{domain}' with " . __PACKAGE__) if $results->{logger};
    my $zonename = $self->{cleanup}->{$results->{domain}}->{zone};
    my $rr = $self->{cleanup}->{$results->{domain}}->{rr};
    my $data = $self->{cleanup}->{$results->{domain}}->{data};
    my $zone = $self->{client}->zone($zonename);
    $results->{logger}->info("Deleting $rr TXT record ($data) in zone $zonename") if $results->{logger};
    if ($zone->remove($rr, undef, 'TXT', $data)) {
        if ($zone->commit()) {
            sleep(5);
            return 1;
        }
    }
    return 0;
}

sub _lsort {
    return sort { length($b) <=> length($a) } @_;
}

1;
