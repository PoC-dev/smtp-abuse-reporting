#!/usr/bin/perl -w

# Copyright 2024-2025 Patrik Schindler <poc@pocnet.net>
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
my $versionstring = '2025-04-17.00';

# Path and name of the database.
my $sqlite_db = "$ENV{HOME}/.abusedb.sqlite";

my ($dbh, $line, $test_db, $retval, $syslog_ts, $abuseaddr, $dnsptr, $ipaddr, $triedlogin, $lookup, $logstamp, $now, $numrows, $res,
    $res_reply, $res_rr, $do_report, $comment, $adjusted_year, $current_day, $current_year, $day, $hour, $minute, $month,
    $month_num, $second, $current_month

);

#-----------------------------------------------------------------------------------------------------------------------------------

my %options = ();
$retval = getopts("dhtv", \%options);

if ( $retval != 1 ) {
    printf(STDERR "Wrong parameter error.\n\n");
}

if ( defined($options{h}) || $retval != 1 ) {
    printf("Usage: smtp-abuse-syslog(.pl) [options]\nOptions:
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
    openlog("smtp-abuse-syslog", "perror,pid", "user");
} else {
    openlog("smtp-abuse-syslog", "pid", "user");
    # Omit debug messages by default.
    setlogmask(127);
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
$dbh = DBI->connect("dbi:SQLite:dbname=$sqlite_db", "", "");
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
    reported TEXT,
    report_id TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS parsed_syslog_idx ON parsed_syslog (logstamp, ipaddr, triedlogin);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}

$dbh->do("CREATE TABLE IF NOT EXISTS contacts (
    abuseaddr TEXT,
    ipaddr TEXT NOT NULL PRIMARY KEY,
    allegedfix TEXT,
    comment TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS contacts_idx ON contacts (abuseaddr);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}

$dbh->do("CREATE TABLE IF NOT EXISTS contacts_report (
    abuseaddr TEXT NOT NULL PRIMARY KEY,
    lastreport TEXT,
    do_report INT NOT NULL DEFAULT 1,
    comment TEXT,
    report_id TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS contacts_report_idx ON contacts_report (lastreport, do_report);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}


# Create predefined statements.
my $sth_insert_syslog = $dbh->prepare("INSERT INTO parsed_syslog (dnsptr, ipaddr, logstamp, triedlogin) VALUES (?, ?, ?, ?);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_query_contact = $dbh->prepare("SELECT COUNT(*) FROM contacts WHERE ipaddr=?;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_insert_contact = $dbh->prepare("INSERT INTO contacts (abuseaddr, ipaddr) VALUES (?, ?);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_query_contacts_report = $dbh->prepare("SELECT do_report, comment FROM contacts_report WHERE abuseaddr=?;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

#-----------------------------------------------------------------------------------------------------------------------------------

$now = localtime();

# Read from stdin, format one line and spit it out again.
foreach $line ( <STDIN> ) {
	chomp($line);
	if ( $line =~ /^(\w{3} [ :0-9]{11}) [\._[:alnum:]]+ postfix\/smtpd\[[0-9]+\]: warning: ([[:print:]]+)\[([[:xdigit:]:.]+)\]: SASL (LOGIN|PLAIN) authentication failed: authentication failure, sasl_username=([[:print:]]+)$/ ) {
		if (defined($1) && defined($2) && defined($3) && defined($5) ) {
            $syslog_ts = $1;
            $dnsptr = $2;
            $ipaddr = $3;
            $triedlogin = $5;


            # The next part is required to estimate year's turn and add the proper year to complement the timestamp to be complete.
            # Suggestion by ChatGPT.
            $syslog_ts =~ /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/;
            ($month, $day, $hour, $minute, $second) = ($1, $2, $3, $4, $5);
            # Convert month abbreviation to month number.
            my %month_map = (
                'Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4,
                'May' => 5, 'Jun' => 6, 'Jul' => 7, 'Aug' => 8,
                'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12
            );
            $month_num = $month_map{$month};
            # Get the current date to help calculate year change (if any).
            $current_year = (localtime)[5] + 1900;
            ($current_month, $current_day) = (localtime)[4, 3];
            $current_month += 1;  # Adjust because localtime returns months 0-11.
            $adjusted_year = $current_year;
            # If the given date is earlier in the year than the current date, consider it last year.
            if ($month_num < $current_month || ($month_num == $current_month && $day < $current_day)) {
                $adjusted_year--;
            }
            # Create a timestamp from the extracted values.
            $logstamp = sprintf("%04d-%02d-%02d %02d:%02d:%02d", $adjusted_year, $month_num, $day, $hour, $minute, $second);


            # Write entry to syslog table.
            syslog(LOG_DEBUG, "SQL: INSERT INTO parsed_syslog (dnsptr, ipaddr, logstamp, triedlogin) VALUES ('%s', '%s', '%s', '%s');",
                $dnsptr, $ipaddr, $logstamp, $triedlogin);
            $sth_insert_syslog->execute($dnsptr, $ipaddr, $logstamp, $triedlogin);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL insert_syslog execution error: %s", $dbh->errstr);
                next;  # Line
            }

            # Query database for an associated contact entry. If it doesn't exist, do the lookup.
            $sth_query_contact->execute($ipaddr);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL query_contact execution error: %s", $dbh->errstr);
            } else {
                ($numrows) = $sth_query_contact->fetchrow;
                if ( defined($dbh->errstr) ) {
                    syslog(LOG_WARNING, "SQL query_contact fetch error: %s", $dbh->errstr);
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

                        # Check contacts_report for a comment. This is for logging purposes only!
                        $sth_query_contacts_report->execute($abuseaddr);
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_NOTICE, "SQL query_contacts_report execution error: %s", $dbh->errstr);
                        } else {
                            ($do_report, $comment) = $sth_query_contacts_report->fetch;
                            if ( defined($dbh->errstr) ) {
                                syslog(LOG_NOTICE, "SQL query_contacts_report fetch error: %s", $dbh->errstr);
                            }
                        }
                        if ( defined($do_report) && defined($comment) ) {
                            syslog(LOG_INFO, "Contact '%s' is already known! Do_report=%d, comment=%s",
                                $abuseaddr, $do_report, $comment);
                        }

                        # Actually insert row into database.
                        syslog(LOG_DEBUG, "SQL: INSERT INTO contacts (abuseaddr, ipaddr) VALUES ('%s', '%s');",
                            $abuseaddr, $ipaddr);
                        $sth_insert_contact->execute($abuseaddr, $ipaddr);
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_WARNING, "SQL insert_contact execution error: %s", $dbh->errstr);
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
    if ( $sth_query_contacts_report ) {
        $sth_query_contacts_report->finish;
    }
    if ( $dbh ) {
        $dbh->disconnect;
    }

    closelog;
}

#-----------------------------------------------------------------------------------------------------------------------------------
# vim: tabstop=4 shiftwidth=4 autoindent colorcolumn=133 expandtab textwidth=132
# -EOF-
