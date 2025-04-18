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
use DateTime;
use DateTime::TimeZone;
use Getopt::Std;
use MIME::Lite;
use Net::Domain qw(hostdomain);
use Sys::Syslog;
#use Time::Piece;

#-----------------------------------------------------------------------------------------------------------------------------------
# Vars.

# This is to be manually incremented on each "publish".
my $versionstring = '2025-04-18.00';

# This needs to be a deliverable email address, because you *will* receive bounce messages!
my $mailfrom = 'abuse-report@' . hostdomain();

# Load mailbody from external file.
my $email_text_file = "$ENV{HOME}/.abuse-mailbody.txt";

my $abusix_disclaimer = 'Abusix is neither responsible nor liable for the content or accuracy of
the abuse being reported in this message. The Abusix Abuse Contact DB
provided only the abuse contact for the originating network for this
report. This free abuse@ address, proxy DB service, is built on top of
the RIR databases. Therefore, if you wish to change or report a
non-working abuse contact address, please get in touch with the parent
ASN operator or the appropriate RIR responsible for managing the
underlying IP address on the abuse contact map. If you have questions
about the DB, please visit https://abusix.com/contactdb/ or email
support@abusix.com.';

# Path and name of the database.
my $sqlite_db = "$ENV{HOME}/.abusedb.sqlite";

my ($abuseaddr, $day, $dbh, $dry_run, $dt, $email_handle, $email_subject, $email_text, $fh, $hour, $ipaddr, $ip_stamp_report,
    $logstamp, $minute, $month, $numrows, $report_id, $retval, $rowid, $second, $test_db, $tmpstr, $utc_dt, $year
);

# Prepare output format for the report itself.
format IP_STAMP_REPORT =
@<<<<<<<<<<<<<<<<<<<<<@<<<<<<<<<<<<<<<<<
$logstamp, $ipaddr
.

# Lines per Page for the Report Writer - essentially disabling pagination.
$==500000000;

#-----------------------------------------------------------------------------------------------------------------------------------
# Initial preparations.

my %options = ();
$retval = getopts("dhntv", \%options);

if ( $retval != 1 ) {
    printf(STDERR "Wrong parameter error.\n\n");
}

if ( defined($options{h}) || $retval != 1 ) {
    printf("Usage: smtp-abuse-report(.pl) [options]\nOptions:
    -d: Enable debug mode
    -h: Show this help and exit
    -n: \"dry run\" mode: don't update database, send mail to sender address
    -t: Test database connection and exit
    -v: Show version and exit\n\n");
    printf("Note that logging is done almost entirely via syslog, facility user.\n");
    exit(0);
} elsif ( defined($options{v}) ) {
    printf('Version %s\n', $versionstring);
    exit(0);
}


# First, check if our mail body file exists and complain if not.
if ( ! -e $email_text_file ) {
    printf(STDERR "Mail body template file '%s' does not exist. Exit.\n", $email_text_file);
    die;
}

# Dry run (do not update database, do not send mail).
if ( defined($options{n}) ) {
    if ( ! -e $sqlite_db ) {
        printf(STDERR "SQLite-Database %s not found. Dry run mode set, no changes permitted. Exit.\n", $sqlite_db);
        die;
    }
    $dry_run = 1;
} else {
    $dry_run = 0;
}

# Test database connection and exit.
if ( defined($options{t}) ) {
    $test_db = 1;
} else {
    $test_db = 0;
}


# Enable debug mode.
if ( defined($options{d}) ) {
    openlog("smtp-abuse-report", "perror,pid", "user");
} else {
    openlog("smtp-abuse-report", "pid", "user");
    # Omit debug messages by default.
    setlogmask(127);
}

#-----------------------------------------------------------------------------------------------------------------------------------
# Read our mail body file.
open($fh, "<", $email_text_file);
if ( $fh ) {
    syslog(LOG_DEBUG, "Init: Successfully read '%s'", $email_text_file);
    local($/) = undef;
    $email_text = <$fh>;
    close($fh);
} else {
    syslog(LOG_ERR, "Error opening mail body template file '%s'. Exit", $email_text_file);
    die;
}

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
# Note: This has to be kept in sync with the definitions in smtp-abuse-syslog.pl.

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
# Note: This is indepentendent from the definitions in smtp-abuse-syslog.pl.

# Create a list of all contacts which have never been sent a report (contacts_report.lastreport IS NULL), or where the last report
# has been sent more than a week ago. Do only if do_report is undefined (NULL), or 1.
my $sth_query_contacts = $dbh->prepare("SELECT DISTINCT contacts.abuseaddr FROM contacts
    LEFT JOIN contacts_report ON (contacts.abuseaddr = contacts_report.abuseaddr)
    WHERE (contacts_report.lastreport IS NULL OR contacts_report.lastreport < datetime('now', '-7 days'))
    AND (do_report=1 OR do_report IS NULL) COLLATE NOCASE;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

# Create a list of all syslog entries for a given abuse address, where 
# - an abusing IP address is not too old (less than 14 days), AND
# - an abusing IP address has not yet been reported (reported IS NULL), AND
# - an abusing IP address is newer then recorded in contacts.allegedfix.
# FIXME: Why not include *all* found records of abuse in the actual report, if we found *recent* abuse records (< 14 days)?
my $query_syslog_common_sql = "FROM parsed_syslog LEFT JOIN contacts ON (parsed_syslog.ipaddr = contacts.ipaddr)
     WHERE contacts.abuseaddr = ? AND logstamp >= datetime('now', '-14 days') AND reported IS NULL AND
     (allegedfix IS NULL OR logstamp >= allegedfix) COLLATE NOCASE;";

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

# Predefined transaction statements.
my $sth_trans_begin = $dbh->prepare("BEGIN TRANSACTION;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_trans_commit = $dbh->prepare("COMMIT;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_trans_rollback = $dbh->prepare("ROLLBACK;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

# Update timestamps.
my $sth_update_contacts_report = $dbh->prepare("INSERT OR REPLACE INTO contacts_report (abuseaddr, report_id, lastreport) VALUES
    (?, ?, datetime('now'));");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}
my $sth_update_syslog = $dbh->prepare("UPDATE parsed_syslog SET reported=datetime('now'), report_id=? WHERE rowid=?;");
if ( defined($dbh->errstr) ) {
    syslog(LOG_ERR, "SQL preparation error: %s", $dbh->errstr);
    die;
}

#-----------------------------------------------------------------------------------------------------------------------------------

# Statistics.
my $contacts_iter_count = 0;
my $syslog_rows_sum_count = 0;
my $sent_mails_count = 0;

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
            $contacts_iter_count++;

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
            $syslog_rows_sum_count = $syslog_rows_sum_count + $numrows;

            # FIXME: Insert "workaround" for not bugging RIRs directly.

            # Get actual records if we have found some.
            if ( $numrows gt 0 ) {
                # Create a report list of abuse addresses.
                $sth_query_syslog->execute($abuseaddr);
                if ( defined($dbh->errstr) ) {
                    syslog(LOG_WARNING, "SQL query_syslog execution error: %s, skipping", $dbh->errstr);
                    next;
                } else {
                    # Create Abuse Report ID.
                    $report_id = sprintf("%08X", rand(0xffffffff));
                    $email_subject = sprintf("Abuse report [%s]: SMTP probes for username/password pairs", $report_id);

                    # Create mail handle for this abuse report.
                    if ( $dry_run eq 0 ) {
                        $email_handle = MIME::Lite->new(
                            From       => $mailfrom,
                            To         => $abuseaddr,
                            CC         => $mailfrom,
                            Subject    => $email_subject,
                            Type       => 'multipart/mixed',
                        );
                    } else {
                        $email_handle = MIME::Lite->new(
                            From       => $mailfrom,
                            To         => $mailfrom,
                            Subject    => $email_subject,
                            Type       => 'multipart/mixed',
                        );
                    }

                    if ( $dry_run eq 0 ) {
                        # Prepare SQL transaction before we do write into the database.
                        syslog(LOG_DEBUG, "SQL BEGIN TRANSACTION");
                        $sth_trans_begin->execute();
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_WARNING, "SQL BEGIN TRANSACTION execution error: %s", $dbh->errstr);
                        }

                        # "Update" contact entry.
                        syslog(LOG_DEBUG, "SQL updating contacts_report entry: %s", $abuseaddr);
                        $sth_update_contacts_report->execute($abuseaddr, $report_id);
                        if ( defined($dbh->errstr) ) {
                            syslog(LOG_WARNING, "SQL sth_update_contacts_report execution error: %s", $dbh->errstr);
                        }
                    }

                    # Open variable as file handle for a given format.
                    open(IP_STAMP_REPORT, ">", \$ip_stamp_report);

                    # Print heading.
                    # FIXME: Is this how headers are created proper?
                    $logstamp = "Timestamp";
                    $ipaddr = "IP Address";
                    write(IP_STAMP_REPORT);

                    # Collect and format individual syslog entries.
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

                            # Calculate timestamp to UTC.
                            if ($logstamp =~ /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/) {
                                ($year, $month, $day, $hour, $minute, $second) = ($1, $2, $3, $4, $5, $6);

                                $dt = DateTime->new(
                                    year      => $year,
                                    month     => $month,
                                    day       => $day,
                                    hour      => $hour,
                                    minute    => $minute,
                                    second    => $second,
                                    time_zone => 'Europe/Berlin',  # Berlin time zone handles both CET and CEST
                                );
                                $utc_dt = $dt->clone->set_time_zone('UTC');

                                # Output the UTC time in the same format
                                $logstamp = sprintf("%s", $utc_dt->strftime('%Y-%m-%d %H:%M:%S'));

                                # Write records to a reporting "file" for later attachment.
                                write(IP_STAMP_REPORT);

                                if ( $dry_run eq 0 ) {
                                    # Update individual syslog rows.
                                    syslog(LOG_DEBUG, "SQL updating syslog entry %d: (%s, %s, %s)",
                                        $rowid, $logstamp, $ipaddr, $report_id);
                                    $sth_update_syslog->execute($report_id, $rowid);
                                    if ( defined($dbh->errstr) ) {
                                        syslog(LOG_WARNING, "SQL sth_update_syslog execution error: %s", $dbh->errstr);
                                    }
                                }
                            } else {
                                syslog(LOG_WARNING, "could not parse timestamp '%s' for UTC conversion, skipping", $logstamp);
                                next;
                            }
                        }
                    }

                    close(IP_STAMP_REPORT);

                    # "Attach" virtual file (explanatory text, and report in $ip_stamp_report).
                    $email_handle->attach(
                        Type        => 'text/plain; charset="us-ascii"',
                        Data        => $email_text . '\n' . $ip_stamp_report,
                    );

                    # Attach abusix disclaimer.
                    $email_handle->attach(
                        Type        => 'text/plain; charset="us-ascii"',
                        Data        => $abusix_disclaimer,
                        Filename    => 'abusix_disclaimer.txt',
                        Disposition => 'attachment',
                    );

                    if ( $dry_run eq 0 ) {
                        # Send this mail.
                        if ( $email_handle->send ) {
                            $sent_mails_count++;
                            syslog(LOG_DEBUG, "SQL COMMIT: Email with %d report entries has (successfully?) been sent", $numrows);

                            $sth_trans_commit->execute();
                            if ( defined($dbh->errstr) ) {
                                syslog(LOG_WARNING, "SQL COMMIT execution error: %s", $dbh->errstr);
                            }
                        } else {
                            syslog(LOG_WARNING, "SQL ROLLBACK: Error sending report mail");

                            $sth_trans_rollback->execute();
                            if ( defined($dbh->errstr) ) {
                                syslog(LOG_WARNING, "SQL ROLLBACK execution error: %s", $dbh->errstr);
                            }
                        }
                    } else {
                        $email_handle->send;
                        $sent_mails_count++;
                        syslog(LOG_DEBUG, "Email with %d report entries has (successfully?) been sent", $numrows);
                    }

                    # Reset variable(s).
                    $ip_stamp_report = undef;
                }
            }
        }
    }
}

if ( $dry_run eq 0 ) {
    syslog(LOG_NOTICE, "Finished work: handled %d contacts, %d syslog rows and have sent %d emails",
        $contacts_iter_count, $syslog_rows_sum_count, $sent_mails_count);
} else {
    syslog(LOG_NOTICE, "Finished work (dry run mode): handled %d contacts, %d syslog rows and have sent %d emails",
        $contacts_iter_count, $syslog_rows_sum_count, $sent_mails_count);
}

#-----------------------------------------------------------------------------------------------------------------------------------

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
    if ( $sth_trans_begin ) {
        $sth_trans_begin->finish;
    }
    if ( $sth_trans_commit ) {
        $sth_trans_commit->finish;
    }
    if ( $sth_trans_rollback ) {
        $sth_trans_rollback->finish;
    }
    if ( $sth_update_contacts_report ) {
        $sth_update_contacts_report->finish;
    }
    if ( $sth_update_syslog ) {
        $sth_update_syslog->finish;
    }
    if ( $dbh ) {
        $dbh->disconnect;
    }

    closelog;
}

#-----------------------------------------------------------------------------------------------------------------------------------
# vim: tabstop=4 shiftwidth=4 autoindent colorcolumn=133 expandtab textwidth=132
# -EOF-
