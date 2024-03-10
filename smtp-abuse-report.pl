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
    printf("Usage: abuse-smtp-report(.pl) [options]\nOptions:
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
    openlog("abuse-smtp-report", "perror,pid", "user");
} else {
    openlog("abuse-smtp-report", "pid", "user");
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
# FIXME: Convert to absolute path in home directory.
$dbh = DBI->connect("dbi:SQLite:dbname=.abusedb.sqlite","","");
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
# Note: This has to be kept in sync with the definitions in smtp-abuse-syslog.pl.

$dbh->do("CREATE TABLE IF NOT EXISTS parsed_syslog (
    dnsptr TEXT NOT NULL,
    ipaddr TEXT NOT NULL,
    logstamp TEXT NOT NULL,
    triedlogin TEXT NOT NULL,
    usestamp TEXT
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
# FIXME: Add timestamp based constraint.
my $sth_query_contacts = $dbh->prepare("SELECT DISTINCT contacts.abuseaddr FROM contacts
    LEFT JOIN contacts_report ON (contacts.abuseaddr = contacts_report.abuseaddr)
    WHERE contacts_report.lastreport IS NULL;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error in: %s", $dbh->errstr);
    die;
}
# FIXME: Add timstamp based constraint to suppress already reported abusing IP addresses.
my $sth_query_syslog = $dbh->prepare("SELECT logstamp, parsed_syslog.ipaddr, dnsptr, triedlogin FROM parsed_syslog
    LEFT JOIN contacts ON (parsed_syslog.ipaddr = contacts.ipaddr)
    WHERE contacts.abuseaddr = ? AND usedstamp IS NULL;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error in: %s", $dbh->errstr);
    die;
}

#-----------------------------------------------------------------------------------------------------------------------------------

# Retrieve current date.
my $now = localtime();

# Query database for contacts entry.
$sth_query_contacts->execute();
if ( defined($dbh->errstr) ) {
    syslog(LOG_WARNING, "SQL execution error in: %s", $dbh->errstr);
} else {
    while ( ($abuseaddr) = $sth_query_contacts->fetchrow ) {
        if ( defined($dbh->errstr) ) {
            syslog(LOG_WARNING, "SQL fetch error in: %s", $dbh->errstr);
        } else {
            syslog(LOG_DEBUG, "Found abuseaddr '%s'", $abuseaddr);
            $sth_query_syslog->execute($abuseaddr);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL execution error in: %s", $dbh->errstr);
            } else {
                # FIXME: Query number of affected rows to skip handling a particular abuseaddr if there are no results.
                while ( ($logstamp, $ipaddr, $dnsptr, $triedlogin) = $sth_query_syslog->fetchrow ) {
                    if ( defined($dbh->errstr) ) {
                        syslog(LOG_WARNING, "SQL fetch error in: %s", $dbh->errstr);
                    } else {
                        # FIXME: Remove microseconds from logstamp.
                        syslog(LOG_DEBUG, "Found entry %s %s %s %s", $logstamp, $ipaddr, $dnsptr, $triedlogin);
                    }
                }
            }
        }
    }
}

#-----------------------------------------------------------------------------------------------------------------------------------

syslog(LOG_DEBUG, "Finished, cleaning up");

# Further cleanup is handled by the END block implicitly.
END {
    if ( $sth_query_contacts ) {
        $sth_query_contacts->finish;
    }
    if ( $sth_query_syslog ) {
        $sth_query_syslog->finish;
    }
    if ( $dbh ) {
        $dbh->disconnect;
    }

    closelog;
}

#-----------------------------------------------------------------------------------------------------------------------------------
# vim: tabstop=4 shiftwidth=4 autoindent colorcolumn=133 expandtab textwidth=132
# -EOF-
