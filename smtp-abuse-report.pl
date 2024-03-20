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
use MIME::Lite;
use Sys::Syslog;
use Time::Piece;

#-----------------------------------------------------------------------------------------------------------------------------------
# Vars.

# This is to be manually incremented on each "publish".
my $versionstring = '2024-03-20.00';

my ($dbh, $test_db, $retval, $abuseaddr, $ipaddr, $logstamp, $numrows, $email_handle, $email_text, $fh, $ip_stamp_report, $rowid,
    @rowids, @abuseaddrs);

# Load mailbody from external file.
my $email_text_file = "$ENV{HOME}/.abuse-mailbody.txt";

#-----------------------------------------------------------------------------------------------------------------------------------

# See: https://alvinalexander.com/perl/perl-getopts-command-line-options-flags-in-perl/

my %options = ();
$retval = getopts("dhntv", \%options);

if ( $retval != 1 ) {
    printf(STDERR "Wrong parameter error.\n\n");
}

if ( defined($options{h}) || $retval != 1 ) {
    printf("Usage: abuse-smtp-report(.pl) [options]\nOptions:
    -d: Enable debug mode
    -h: Show this help and exit
    -n: No send mail, \"dry run\"
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

# First, check if our mail body file exists and complain if not.
if ( -e $email_text_file ) {
    open($fh, "<", $email_text_file);
    if ( $fh ) {
        syslog(LOG_DEBUG, "Init: Successfully read '%s'", $email_text_file);
        local($/) = undef;
        $email_text = <$fh>;
        close($fh);
    } else {
        printf(STDERR "Error opening mail body template file '%s'. Exit.\n", $email_text_file);
        syslog(LOG_ERR, "Error opening mail body template file '%s'. Exit", $email_text_file);
        die;
    }
} else {
    printf(STDERR "Mail body template file '%s' does not exist. Exit.\n", $email_text_file);
    syslog(LOG_ERR, "Mail body template file '%s' does not exist. Exit", $email_text_file);
    die;
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
# Note: This has to be kept in sync with the definitions in smtp-abuse-syslog.pl.

$dbh->do("CREATE TABLE IF NOT EXISTS parsed_syslog (
    dnsptr TEXT NOT NULL,
    ipaddr TEXT NOT NULL,
    logstamp TEXT NOT NULL,
    triedlogin TEXT NOT NULL,
    lastused TEXT
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
    ipaddr TEXT NOT NULL PRIMARY KEY
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
    lastreport TEXT
    );");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}
$dbh->do("CREATE INDEX IF NOT EXISTS contacts_report_idx ON contacts_report (lastreport);");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL do error: %s", $dbh->errstr);
    die;
}


# Create predefined statements.

# Create a list of all contacts which have never been sent a report (contacts_report.lastreport IS NULL), or where the last report
# has been sent more than a week ago.
my $sth_query_contacts = $dbh->prepare("SELECT DISTINCT contacts.abuseaddr FROM contacts
    LEFT JOIN contacts_report ON (contacts.abuseaddr = contacts_report.abuseaddr)
    WHERE contacts_report.lastreport IS NULL OR contacts_report.lastreport < date('now', '-7 days');");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

# Create a list of all syslog entries for a given abuse address, where 
# - an abuse address is not too old (less than 14 days) AND,
# - an abuse address has not yet been reported (lastused IS NULL);
my $query_syslog_common_sql = "FROM parsed_syslog LEFT JOIN contacts ON (parsed_syslog.ipaddr = contacts.ipaddr)
WHERE contacts.abuseaddr = ? AND logstamp >= date('now', '-14 days') AND lastused IS NULL;";

my $sth_query_syslog = $dbh->prepare("SELECT parsed_syslog.rowid, logstamp, parsed_syslog.ipaddr " . $query_syslog_common_sql);
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

# Same as above, but just return the number of records.
my $sth_query_syslog_count = $dbh->prepare("SELECT COUNT(*) " . $query_syslog_common_sql); 
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

#-----------------------------------------------------------------------------------------------------------------------------------

# Prepare output format for the report itself.
format IP_STAMP_REPORT =
@<<<<<<<<<<<<<<<<<<<<<@<<<<<<<<<<<<<<<<<
$logstamp, $ipaddr
.

#format STDOUT_TOP =
#.

# Lines per Page for the Report Writer - essentially disabling pagination.
$==500000000;


# Query database for contacts entry.
$sth_query_contacts->execute();
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL query_contacts execution error: %s", $dbh->errstr);
    die;
} else {
    # Loop through eligible abuse addresses.
    while ( ($abuseaddr) = $sth_query_contacts->fetchrow ) {
        if ( defined($dbh->errstr) ) {
            syslog(LOG_WARNING, "SQL query_contacts fetch error: %s", $dbh->errstr);
            next;
        } else {
            # How many syslog entries do we have for the given abuseaddr?
            $sth_query_syslog_count->execute($abuseaddr);
            if ( defined($dbh->errstr) ) {
                syslog(LOG_WARNING, "SQL query_syslog_count execution error: %s, assuming 0 rows have been found", $dbh->errstr);
                $numrows = 0;
            } else {
                ($numrows) = $sth_query_syslog_count->fetchrow;
                if ( defined($dbh->errstr) ) {
                    syslog(LOG_WARNING, "SQL query_syslog_count fetch error: %s, assuming 0 rows have been found", $dbh->errstr);
                    $numrows = 0;
                }
            }

            # Get actual records if we have found some.
            if ( $numrows gt 0 ) {
                syslog(LOG_DEBUG, "Got abuseaddr '%s'", $abuseaddr);

                # Add abuseaddrs to an array, for later update of contacts_report.abuseaddr from split array.
                push(@abuseaddrs, $abuseaddr);

                # Create a report list of abuse addresses.
                $sth_query_syslog->execute($abuseaddr);
                if ( defined($dbh->errstr) ) {
                    syslog(LOG_WARNING, "SQL query_syslog execution error: %s, skipping", $dbh->errstr);
                    next;
                } else {
                    # Create mail handle for this abuse report.
                    my $email_handle = MIME::Lite->new(
                        From    => 'poc@pocnet.net',
                        To      => 'poc@pocnet.net',
                        Subject => 'Abuse report: SMTP probes for username/password pairs',
                        Type    => 'multipart/mixed',
                    );

                    $email_handle->attach(
                        Type     => 'text/plain; charset="us-ascii"',
                        Data     => $email_text,
                    );

                    # Open variable as file handle for a given format.
                    open(IP_STAMP_REPORT, ">", \$ip_stamp_report);

                    while ( ($rowid, $logstamp, $ipaddr) = $sth_query_syslog->fetchrow ) {
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_WARNING, "SQL query_syslog fetch error: %s, skipping", $dbh->errstr);
                            next;
                        } else {
                            # Remove microseconds from logstamp.
                            $logstamp =~ /^([0-9-]+ [0-9:]+)\.[0-9]{3}$/;
                            if ( defined($1) ) {
                                $logstamp = $1;
                            }

                            # Push rowid to array for later UPDATE.
                            push(@rowids, $rowid);
                            syslog(LOG_DEBUG, "Found syslog %s %s (%d)", $logstamp, $ipaddr, $rowid);

                            # Write records to a reporting "file" for later attachment.
                            write(IP_STAMP_REPORT);
                        }
                    }

                    close(IP_STAMP_REPORT);

                    # Attach virtual file (report in $ip_stamp_report).
                    $email_handle->attach(
                        Type        => 'text/plain; charset="us-ascii"',
                        Data        => $ip_stamp_report,
                        Filename    => 'report.txt',
                        Disposition => 'attachment',
                    );

                    # Send this mail.
                    if ( $email_handle->send ) {
                        syslog(LOG_DEBUG, "Email has (hopefully) been sent");
                        # FIXME: Now, update the records we've touched above with the current time stamp.
                    }

                    # Reset variables.
                    @rowids = undef;
                }
            } else {
                syslog(LOG_DEBUG, "No recent syslog rows for abuseaddr '%s', skipping", $abuseaddr);
            }

        # Reset variables.
        @abuseaddrs = undef;
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
    if ( $sth_query_syslog_count ) {
        $sth_query_syslog_count->finish;
    }
    if ( $dbh ) {
        $dbh->disconnect;
    }

    closelog;
}

#-----------------------------------------------------------------------------------------------------------------------------------
# vim: tabstop=4 shiftwidth=4 autoindent colorcolumn=133 expandtab textwidth=132
# -EOF-
