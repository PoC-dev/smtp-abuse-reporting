This is a collection of Perl scripts to automate the reporting of abusing IP addresses to the respective responsible contact address. I haven't found a readymade solution for my particular scenario which shows roughly 200 probes for combinations of logins and passwords on my SMTP server. A number which increased manifold compared to January 2024.

These probes come from many different IP addresses all over the world but use common or very similar login names. The pattern shown strongly suggests these are hosts which have been hijacked and part of a centrally orchestrated botnet.

Just blocking them with Fail2Ban is not feasible. A given IP address probes not very frequently.

## Description.
The first part (script) collects log data:
- filter out postfix syslog messages stating *authentication failure*,
- populate a SQLite table with the respective information from the syslog messages,
- retrieve the abuse contact associated with a given IP address with DNS queries to the [Abusix  Abuse Contact DB](https://docs.abusix.com/abuse-contact-db/5BScLdS3SxHV1giQYpXpKm), and save the found contact address.

**Note:** I'm deliberately **not** using Systemd. The parser script relies on good old *syslog* log files, and `logtail` being used to feed just the added lines to it. You probably need to adjust this if you rely on Systemd facilities.

The second part (script) is meant to generate reports by aggregating collected data to the derived abuse contact address. It takes into account:
- New IP addresses since the last report has been sent,
- a reminder about addresses which already have been reported earlier but still commit abuse.

It also updates timestamps in the respective tables accordingly after a particular report has been sent.

**Note:** The second part is still in early development phase, and not yet functional. The syslog parser is in an usable state, so data collection can commence.

## Files.
- `smtp-abuse-syslog.pl` is the parser script which populates the found error messages into the SQLite database.
- `smtp-abuse-report.pl` is the reporting script which sends out automated email to the found abuse email addresses.
- `~/.abusedb.sqlite` is the SQLite database which is automatically created by any of the aforementioned scripts if not existing.

## Installation.
I recommend copying the scripts to the home directory of a user who's allowed to read log files. For that user, I'm creating a `~/bin` directory to hold this (and other) scripts.

Next, install prerequisites. Example for Debian 12:
```
apt-get install libdbd-sqlite3-perl libmime-lite-perl libnet-dns-perl
```
You can always just run `./bin/smtp-abuse-syslog.pl` to check for errors about missing perl modules. If there are no more, it waits for data on stdin. Quit with EOF (`Ctrl-D`).

Next, use the archived logs to fill the database with inital data:
```
( zcat /var/log/mail.log.4.gz /var/log/mail.log.3.gz /var/log/mail.log.2.gz; cat /var/log/mail.log.1; ) |~/bin/smtp-abuse-syslog.pl -d
```
Finally, create a cronjob like the following:
```
51 * * * *  /usr/sbin/logtail -f /var/log/mail.log -o .smtp-abuse-syslog-offset |bin/smtp-abuse-syslog.pl
```
Because there is not yet a *~/.smtp-abuse-syslog-offset* file, the omitted current log file will now be parsed entirely and entries added. With that, there is no opportunity to miss any entries.

Both scripts support command line options:
```
-d: Enable debug mode
-h: Show help and exit
-t: Test database connection and exit
-v: Show version and exit
```
Note that logging is done almost entirely via syslog, facility user. Debug mode switches on concurrent logging to stderr.

### Database layout.
The aforementioned `.abusedb.sqlite` contains the following database tables and fields:
- *parsed_syslog* -- values derived from syslog lines
  - dnsptr -- PTR for the abusing IP address
  - ipaddr -- abusing IP address
  - logstamp -- timestamp from syslog
  - triedlogin -- login name which was attempted
  - usestamp -- timestamp when this record was last used (reported); this is *not* populated by `smtp-abuse-syslog.pl`
- *parsed_syslog_idx* on logstamp, ipaddr, triedlogin for quicker SQL handling
- *contacts* -- individual abusing IP addresses with their respective abuse contact address
  - abuseaddr -- abuse contact address for a given IP address
  - ipaddr -- abusing IP address, see also table *parsed_syslog*
- *contacts_idx* on abuseaddr for quicker SQL handling
- *contacts_report* -- keeping track when a given abuse contact address received a report
  - abuseaddr -- abuse contact address, see also table *contacts*
  - lastreport -- timestamp when this particular contact last received a report
- *contacts_report_idx* on lastreport for quicker SQL handling

## ToDos.
- Finish the reporting part of this project.
- Standard syslog format has no field for the current year. This **will** make the parser fail at year's turnaround, when suddenly after December January follows in the same log run. What to do about this?

----

2024-03-12, poc@pocnet.net
