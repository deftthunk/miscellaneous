#!/usr/bin/perl

## // shunpunt \\ - search for expiring (72+ hour) shuns and determine if they are active
##
##
## Shunpunt parses the last 72 hours of log data on both servers
## for "expired" IP addresses found in '/reports/OldBlocks.txt'. Addresses with no
## hits will turn up in your home directory as a file called 'shun_releases.txt'.
## Addresses with hits will be put in a report named 'shun_active.txt'. The former
## should be visually checked and then emailed to <people>.
## The latter, shuns being held back, must be emailed to <another person>.
##
##
## How to Use:
## user@system ~]$ shunpunt
##
##
## Things to Note:
## -Execution of this script need only happen on one server. Shunpunt takes
## care of checking the other server automatically.
## -Starting an instance and then killing it prematurely will not kill the remote
## invocation on the other server. You must either kill it manually or let it finish
## -Script only works on an account that uses passwordless SSH RSA keys


use strict;
use warnings;
use IO::Zlib;
use Getopt::Long qw( :config no_ignore_case );
use threads;
use Thread::Queue;
use Time::Local;
use IO::Socket;
require '/scripts/lib/shunpunt/FWBlockRecords.pl';
require '/scripts/lib/CountryLookup.pl';
require '/scripts/lib/LogRetrieve.pl';
require '/scripts/lib/IDSLogin.pl';
require '/scripts/lib/Auth.pl';


############>> Global Variables <<############
my $shun_file = '/reports/OldBlocks.txt';
my $server1_ip = '1.2.3.4';
my $server2_ip = '5.6.7.8';
my $num_hours = 72;
my $executing_path = '/scripts/shunpunt';
chomp(my $user = `whoami`);
chomp(my $date = join('.', split(/\//, `date +%D`)));
my $file_out_active = "/home/$user/shun_active_$date.txt";
my $file_out_releases = "/home/$user/shun_releases_$date.txt";
my( $fout_active, $fout_releases );
my $max_threads = 9;
##############################################

open( $fout_active, "> $file_out_active" ) or die "\nCannot create file $file_out_active\n";
open( $fout_releases, "> $file_out_releases" ) or die "\nCannot create file $file_out_releases\n";

setpriority( 0, $$, 12 );    ## nice the script (set to 12)


### verify that the same version of shunpunt is running on both server's
sub sum_check
{
    return qx/sha1sum $executing_path/;
}

### which server is this??
sub which_server
{
    return (qx/uname -n/ =~ /((?:sysA|sysB)server)/)[0];
}

sub get_input
{
    my @input;
    my %opt_hash;

    GetOptions(
        \%opt_hash,
        'remote|r'
    );
    
    if( @ARGV ) {
        foreach( @ARGV ) {
            my $file;
            if( $_ =~ /.*\.gz$/ ) {
                open( $file, "gzip -dc $_ |" ) or die( "Error: Cannot open '$_'\n" );
            }
            else {
                open( $file, "< $_" ) or die( "Error: Cannot open '$_'\n" );
            }
            push( @input, \$file );
        }
    }
    else {    ## DEFAULT: look at last 72 hours
        my $tmp_array_ref = logRetrieve($num_hours);
        foreach( @{$tmp_array_ref} ) {
            my $file;
            if( $_ =~ /.*\.gz$/ ) {
                open( $file, "gzip -dc $_ |" ) or die( "Error: Cannot open '$_'\n" );
            }
            else {
                open( $file, "< $_" ) or die( "Error: Cannot open '$_'\n" );
            }
            push( @input, \$file );
        }
    }

    return( \@input, \%opt_hash );
}

sub parse
{
    my $fh = ${${$_[0]}};
    my $t_queue = ${$_[1]};
    my %file_hash = %{$_[2]};
    my %data;
    my $shun_regex = qr/Shun(\D+):\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

    while( <$fh> ) {
        if( $_ =~ /$shun_regex/ ) {
            if( exists $file_hash{ $2 } ) {
                if( $1 eq 'ned packet' ) {
                    $data{ $2 }++;
                }
                ## if "Shun added" is found, it is too early to remove block
                elsif( $1 eq ' added' ) {
                    $data{ $2 } = -1;
                }
            }
        }
    }

    close $fh;
    $t_queue->dequeue_nb;    ## signal thread completion by removing
                            ## an element from the shared queue
    return \%data;
}

sub grab_file
{
    my %input_file;
    open( my $fh, "< $_[0]" );

    while( <$fh> ) {
        chomp;
        $input_file{ $_ } = 0;
    }

    close $fh;
    return \%input_file;
}

# make connection to other server; start identical process
sub r_connect
{
    chomp( my $user = qx/whoami/ );

    if( which_server() eq 'server1' ) {
        system( "ssh -l $user -R 18400:localhost:18400 1.2.3.4 '/scripts/shunpunt -r'" );
    }
    elsif( which_server() eq 'server2' ) {
        system( "ssh -l $user -R 18400:localhost:18400 5.6.7.8 '/scripts/shunpunt -r'" );
    }
    else {
        print $fout_active "Cannot determine which server I'm on!\n";
        print $fout_releases "Cannot determine which server I'm on!\n";
        exit;
    }
}

sub r_listen
{
    my $sock = new IO::Socket::INET (
                   LocalAddr => 'localhost',
                   LocalPort => '18400',
                   Proto => 'tcp',
                   Listen => 1,
                   Reuse => 1,
               );

    die "Could not create socket: $!\n" unless $sock;

    my $new_sock = $sock->accept();
    my %remote_hash;

    while( <$new_sock> ) {
        chomp;
        my( $key, $value ) = split( /,/, $_ );
        $remote_hash{ $key } = $value;
    }

    return \%remote_hash;
}

sub output
{
    ## ip => [hits, country, description]
    our %bad_hash = %{$_[0]};
    my %good_hash = %{$_[1]};

    sub cntrySort
    {
        $bad_hash{$b}[1] cmp $bad_hash{$a}[1];
    }

    print $fout_active "\nShuns which still had activity:\n\n";
    foreach my $shun ( sort cntrySort keys %bad_hash ) {
        print $fout_active "< $shun > - $bad_hash{$shun}[1] - $bad_hash{$shun}[0] hits\n";
        if( $bad_hash{$shun}[2] ) {
            print $fout_active "$bad_hash{$shun}[2]\n";
        }
        else {
            print $fout_active "Shun may not exist\n";
        }
        print $fout_active "\n----------------\n\n";
    }

    print $fout_releases "Admins,\n\n";
    print $fout_releases "Below is a list of IP addresses which need to be\n";
    print $fout_releases "released from their firewall shuns.\n\n";
    print $fout_releases "Thanks,\n";
    print $fout_releases "SOC Team\n\n";

    foreach my $noshun ( sort keys %good_hash ) {
        if( $good_hash{ $noshun }[0] == 0 ) {
            print $fout_releases "No Shun $noshun\n";
        }
    }
}

sub main
{
    my $sum = sum_check();
    my( $input, $options ) = get_input();
    my $file_hash;

    if(( -e $shun_file ) && ( -r $shun_file )) {
        $file_hash = grab_file( $shun_file );
    }
    else {
        print "\nFile \'$shun_file\' does not exist or does not have read permissions...\n";
        exit;    
    }

    my %final_hash;
    my( @thr_array, @thr_array2 );
    my( $browser, $username, $password );
    my $counter = 0;
    my $queue = new Thread::Queue;    ## put an element on the queue to signal
                                    ## an active thread

    if( ! ${$options}{'remote'} ) {
        print "\n::App Login::\n";
        ( $username, $password ) = auth();    ## grab Webapp credentials for login later
        push( @thr_array2, threads->create( \&r_connect ) );
        push( @thr_array2, threads->create( \&r_listen ) );
    }

    ## load each logfile handle onto its own thread, provided # of active threads
    ## does not exceed $max_threads. if $max_threads is reached, stall parent process
    ## until a thread finishes. remove thread from FIFO queue and get its return data
    foreach( @{$input} ) {
        push( @thr_array, threads->create( \&parse, \$_, \$queue, $file_hash ) );
        $queue->enqueue("placeholder");

        if( $queue->pending > $max_threads ) {
            while( $queue->pending > $max_threads ) {
                sleep 0.001;
            }
        }
    }

    ## for each thread, print data, clean up and close properly
    foreach( 0 .. $#thr_array ) {
        my $ReturnData = $thr_array[$_]->join();
        unless ( ! %{$ReturnData} ) {
            foreach my $ip ( keys %{$ReturnData} ) {
                if( ${$ReturnData}{ $ip } == -1 ) {
                    $final_hash{ $ip } = [-1];
                }
                elsif( exists $final_hash{ $ip } && $final_hash{ $ip} != -1 ) {
                    ${$final_hash{ $ip }}[0] += ${$ReturnData}{ $ip };
                }
                elsif( ! exists $final_hash{ $ip } ) {
                    $final_hash{ $ip } = [${$ReturnData}{ $ip }];
                }
            }
        }
    }

    ## if remote, serialize and send data
    if( ${$options}{'remote'} ) {
        my $sock = new IO::Socket::INET (
                 PeerAddr => 'localhost',
                 PeerPort => '18400',
                 Proto => 'tcp',
        );

        die "Could not create socket: $!\n" unless $sock;
        foreach( keys %final_hash ) {
            print $sock "$_,${$final_hash{ $_ }}[0]\n";
        }
        close($sock);
    }
    else {
        ## if not executing as remote client, assimilate remote data
        my $ReturnData2 = $thr_array2[1]->join();
        unless ( ! %{$ReturnData2} ) {
            foreach my $ip ( keys %{$ReturnData2} ) {
                if( ${$ReturnData2}{ $ip } == -1 ) {
                    $final_hash{ $ip } = [-1];
                }
                elsif( exists $final_hash{ $ip } && $final_hash{ $ip} != -1 ) {
                    ${$final_hash{ $ip }}[0] += ${$ReturnData2}{ $ip };
                }
                elsif( ! exists $final_hash{ $ip } ) {
                    $final_hash{ $ip } = [${$ReturnData2}{ $ip }];
                }
                elsif( $ip eq 'error' ) {
                    print "\nRemote Server Error:\n";
                    print ${$ReturnData2}{ $ip };
                }
            }
        }
        ## if an OldBlocks.txt IP isn't in the hash, set to 'zero' hits
        foreach my $file_ip ( keys %{$file_hash} ) {
            if( ! exists $final_hash{ $file_ip } ) {
                ${$final_hash{ $file_ip }}[0] = 0;
            }
        }
        ## create a seperate report to detail shuns still seeing activity,
        ## even though they are being released.
        my %active_hash;
        foreach( keys %final_hash ) {
            if( ${$final_hash{$_}}[0] > 0 ) {
                $active_hash{$_} = \@{$final_hash{$_}};
            }
        }

        my $active = countryLookup( \%active_hash );        ## determine IP's country of orgin
        $browser = idsLogin( $username, $password );        ## authenticate to IDS webapp
        $active = grabBlockDescr( $browser, $active );        ## pull out shun descriptions for report
        output( $active, \%final_hash );                    ## format and print reports

        close $fout_active;
        close $fout_releases;

        print "\n-> Check files for errors, then run these commands:\n";
        print "mail -s 'IDS Shun Release List' admins\@email.com < /home/$user/shun_releases_$date.txt\n";
        print "mail -s 'Shun Holds' team\@email.com < /home/$user/shun_active_$date.txt\n";
    }
}

main();
exit;

