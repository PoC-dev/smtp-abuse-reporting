#!/usr/bin/perl -w

# Copyright 2024 Patrik Schindler <poc@pocnet.net>
#
# This is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
#
# It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA or get it at http://www.gnu.org/licenses/gpl.html
#
#-----------------------------------------------------------------------------------------------------------------------------------

use strict;
no strict "subs"; # For allowing symbolic names for syslog priorities.
use warnings;
use DBI;
use Getopt::Std;
use Sys::Syslog;
use Time::Piece;
use Net::DNS;

#-----------------------------------------------------------------------------------------------------------------------------------
# Vars.

# This is to be manually incremented on each "publish".
my $versionstring = '2024-03-10.00';

my ($dbh, $line, $test_db, $retval, $syslog_ts, $abuseaddr, $dnsptr, $ipaddr, $triedlogin, $lookup, $logstamp, $numrows, $res,
$res_reply, $res_rr);

#-----------------------------------------------------------------------------------------------------------------------------------

# See: https://alvinalexander.com/perl/perl-getopts-command-line-options-flags-in-perl/

my %options = ();
$retval = getopts("dhtv", \%options);

if ( $retval != 1 ) {
    printf(STDERR "Wrong parameter error.\n\n");
}

if ( defined($options{h}) || $retval != 1 ) {
    printf("Usage: abuse-smtp-syslog(.pl) [options]\nOptions:
    -d: Enable debug mode
    -h: Show this help and exit
    -t: Test database connection and exit
    -v: Show version and exit\n\n");
    printf("Note that logging is done almost entirely via syslog, facility user.\n");
    exit(0);
} elsif ( defined($options{v}) ) {
    printf('Version %s\n', $versionstring);
    exit(0);
}


# Enable debug mode.
if ( defined($options{d}) ) {
    openlog("abuse-smtp-syslog", "perror,pid", "user");
} else {
    openlog("abuse-smtp-syslog", "pid", "user");
    # Omit debug messages by default.
    # FIXME: What is the correct way to handle this with symbolic names?
    setlogmask(6);
}

# Test database connection and exit.
if ( defined($options{t}) ) {
    $test_db = 1;
} else {
    $test_db = 0;
}

#-----------------------------------------------------------------------------------------------------------------------------------

# Now let the game begin!
if ( $test_db == 1 ) {
    printf("Connecting to database...\n");
}
syslog(LOG_DEBUG, "Init: Connecting to database");
$dbh = DBI->connect("dbi:SQLite:dbname=$ENV{HOME}/.abusedb.sqlite", "", "");
if ( ! defined($dbh) ) {
    if ( $test_db == 1 ) {
        printf(STDERR "Connection to database failed: %s\n", $dbh->errstr);
    }
    syslog(LOG_ERR, "Init: connection to database failed: %s", $dbh->errstr);
    die;
} elsif ( defined($dbh) && $test_db == 1 ) {
    printf("Database connection established successfully.\n");
    exit(0);
}

#-----------------------------------------------------------------------------------------------------------------------------------
# Create tables, just in case they don't yet exist.
# Note: This has to be kept in sync with the definitions in smtp-abuse-report.pl.

$dbh->do("CREATE TABLE IF NOT EXISTS parsed_syslog (
    dnsptr TEXT NOT NULL,
    ipaddr TEXT NOT NULL,
    logstamp TEXT NOT NULL,
    triedlogin TEXT NOT NULL,
    lastused TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS parsed_syslog_idx ON parsed_syslog (logstamp, ipaddr, triedlogin);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}

$dbh->do("CREATE TABLE IF NOT EXISTS contacts (
    abuseaddr TEXT,
    ipaddr TEXT NOT NULL PRIMARY KEY
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS contacts_idx ON contacts (abuseaddr);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}

$dbh->do("CREATE TABLE IF NOT EXISTS contacts_report (
    abuseaddr TEXT NOT NULL PRIMARY KEY,
    lastreport TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS contacts_report_idx ON contacts_report (lastreport);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error in: %s", $dbh->errstr);
    die;
}


# Create predefined statements.
my $sth_insert_syslog = $dbh->prepare("INSERT INTO parsed_syslog (dnsptr, ipaddr, logstamp, triedlogin) VALUES (?, ?, ?, ?);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error in: %s", $dbh->errstr);
    die;
}
my $sth_query_contact = $dbh->prepare("SELECT COUNT(*) FROM contacts WHERE ipaddr=?;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error in: %s", $dbh->errstr);
    die;
}
my $sth_insert_contact = $dbh->prepare("INSERT INTO contacts (abuseaddr, ipaddr) VALUES (?, ?);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error in: %s", $dbh->errstr);
    die;
}

#-----------------------------------------------------------------------------------------------------------------------------------

# Retrieve current year.
# FIXME: This *will* fail at year's turnaround, when suddenly after December January follows in the same log run.
#        Ideally, Syslog would include the log entry year.
my $now = localtime();

# Read from stdin, format one line and spit it out again.
foreach $line ( <STDIN> ) {
	chomp($line);
	if ( $line =~ /^(\w{3} [ :0-9]{11}) [\._[:alnum:]]+ postfix\/smtpd\[[0-9]+\]: warning: ([[:print:]]+)\[([[:xdigit:]:.]+)\]: SASL (LOGIN|PLAIN) authentication failed: authentication failure, sasl_username=([[:print:]]+)$/ ) {
		if (defined($1) && defined($2) && defined($3) && defined($5) ) {
            # Sort into variables.
            $dnsptr = $2;
            $ipaddr = $3;
            $triedlogin = $5;

            # Format date and time to a timestamp.
            $syslog_ts = Time::Piece->strptime($now->year . " " . $1, "%Y %b %e %T");
            $logstamp = $syslog_ts->strftime("%Y-%m-%d %T.000");

            # Write entry to syslog table.
            syslog(LOG_DEBUG, "SQL: INSERT INTO parsed_syslog (dnsptr, ipaddr, logstamp, triedlogin) VALUES ('%s', '%s', '%s', '%s');",
                $dnsptr, $ipaddr, $logstamp, $triedlogin);
            $sth_insert_syslog->execute($dnsptr, $ipaddr, $logstamp, $triedlogin);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL execution error in: %s", $dbh->errstr);
                next;  # Line
            }

            # Query database for an associated contact entry. If it doesn't exist, do the lookup.
            $sth_query_contact->execute($ipaddr);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL execution error in: %s", $dbh->errstr);
            } else {
                ($numrows) = $sth_query_contact->fetchrow;
                if ( defined($dbh->errstr) ) {
                    syslog(LOG_WARNING, "SQL fetch error in: %s", $dbh->errstr);
                } else {
                    if ( $numrows eq 0 ) {
                        # Reverse IP address bytes and build DNS lookup string.
                        $ipaddr =~ /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/;
                        $lookup = sprintf("%d.%d.%d.%d.abuse-contacts.abusix.zone", $4, $3, $2, $1);

                        # Do DNS query.
                        $res = Net::DNS::Resolver->new;
                        $res_reply = $res->search($lookup, "TXT");
                        if ( defined($res_reply) ) {
                            foreach $res_rr ($res_reply->answer) {
                                if ( $res_rr->type eq 'TXT' ) {
                                    $abuseaddr = $res_rr->txtdata;
                                    last; # We're supposed to have just one entry there anyway.
                                }
                            }
                        } else {
                            syslog(LOG_WARNING, "Abusix-Query: No result for query %s: %s", $lookup, $res->errorstring);
                        }

                        # Actually insert row into database.
                        syslog(LOG_DEBUG, "SQL: INSERT INTO contacts (abuseaddr, ipaddr) VALUES ('%s', '%s');",
                            $abuseaddr, $ipaddr);
                        $sth_insert_contact->execute($abuseaddr, $ipaddr);
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_WARNING, "SQL execution error in: %s", $dbh->errstr);
                            next;  # Line
                        }
                    } else {
                        syslog(LOG_DEBUG, "Contact entry for %s already existing.", $ipaddr);
                    }
                }
            }
            $dnsptr = $ipaddr = $triedlogin = undef;
		}
	}
}

#-----------------------------------------------------------------------------------------------------------------------------------

syslog(LOG_DEBUG, "Finished, cleaning up");

# Further cleanup is handled by the END block implicitly.
END {
    if ( $sth_insert_syslog ) {
        $sth_insert_syslog->finish;
    }
    if ( $sth_query_contact ) {
        $sth_query_contact->finish;
    }
    if ( $sth_insert_contact ) {
        $sth_insert_contact->finish;
    }
    if ( $dbh ) {
        $dbh->disconnect;
    }

    closelog;
}

#-----------------------------------------------------------------------------------------------------------------------------------
# vim: tabstop=4 shiftwidth=4 autoindent colorcolumn=133 expandtab textwidth=132
# -EOF-
