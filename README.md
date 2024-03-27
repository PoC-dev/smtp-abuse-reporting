This is a collection of Perl scripts to automate the reporting of abusing IP addresses to the respective responsible contact address. I haven't found a readymade solution for my particular scenario which shows many probes a day for combinations of logins and passwords on my SMTP server. A number which increased manifold compared to January 2024.

These probes come from many different IP addresses all over the world but use common or very similar login names. The pattern shown strongly suggests these are hosts which have been hijacked and part of a centrally orchestrated botnet.

Just blocking them with Fail2Ban is not feasible. A given IP address probes not very frequently. A better approach would be to send appropriate reports to the respective abuse addresses.

## Description.
### Files.
- `smtp-abuse-syslog.pl` is the parser script which populates the found error messages into the SQLite database.
- `smtp-abuse-report.pl` is the reporting script which sends out automated email to the found abuse email addresses according to SQLite database content.
- `~/.abusedb.sqlite` is the SQLite database to hold actual data. It is automatically created by any of the aforementioned scripts if not existing.
- `~/.abuse-mailbody.txt` is a greeting text expected to be plain us-ascii which is sent as mail body. It must be provided manually. Example:
```
Dear Madams and Sirs,

for some weeks now I'm experiencing probes for combinations of logins
and passwords to my SMTP server myhost.example.com (0.0.0.0). A number
which increased manifold compared to January 2024.

These probes come from many different IP addresses all over the world.
They show a pattern, though. Probed addresses are contextual to the
probed server (mine), and probed logins are common or very similar login
names, probably derived from scraping of real email addresses.  The
pattern shown strongly suggests these are hosts which have been hijacked
and are part of a centrally orchestrated botnet. All of these probes
connect to the usual SMTP TCP port 25. (My system doesn't use any other
ports for mail delivery.)

This is an example (!) syslog excerpt:
Mar 20 21:29:15 leela postfix/smtpd[50701]: warning: unknown[0.0.0.0]:
SASL LOGIN authentication failed: authentication failure,
sasl_username=john.doe@example.com

Because each individual IP address probes very infrequently, blocking
them is largely moot and might impose more collateral damage, such as
undeliverable regular emails.

My system logged at least one SMTP probe from one or more IP addresses
under your responsibility as described above. The abusing IP addresses
and time of occurrence are shown in the attached report file. The report
contains only IP addresses which were committing probes within the last
two weeks. Shown time stamps are for time zone
INSERT_LOCAL_TIME_ZONE_HERE (UTC +xx00), time format is 24 hr clock.

I kindly ask you to have a look at the attached report, and take
appropriate action. Thank you for your understanding and support. Do not
hesitate to contact me if you experience any additional questions.

Please note that I have used the Abusix service to automatically obtain
a complaint address to a given IP address. Abusix demands attribution to
their service as found in the attachment abusix_disclaimer.txt.

With kind Regards,
```
These scripts are meant to be run as `cron` jobs. See installation section below.

### Log parsing: `smtp-abuse-syslog.pl`.
The first part (script) collects log data:
- filter out postfix syslog messages stating *authentication failure*,
- populate the database table *parsed_syslog* with the respective information from the syslog messages,
- retrieve the abuse contact associated with a given IP address with DNS queries to the [Abusix  Abuse Contact DB](https://docs.abusix.com/abuse-contact-db/5BScLdS3SxHV1giQYpXpKm), and save the found contact address along with the IP address in the *contacts* table.

A sample syslog entry looks like this:
```
Mar 24 13:01:16 myhost postfix/smtpd[494]: warning: unknown[0.0.0.0]: SASL PLAIN authentication failed: authentication failure, sasl_username=john.doe@example.com
```

I've experienced Debian does log the *sasl_username* while RHL (derivatives) do not. The script's regular expressions expect to be able to extract the sasl_username for statistical purpses, as well as further refinement about record selection for a central mail hub serving many domains. At the moment, the *parsed_syslog.triedlogin* field is not used by the reporter script, though.

**Note:** I'm deliberately **not** using Systemd. The parser script relies on good old *syslog* log files, and `logtail` being used to feed just the added lines to it. You need to adjust this if you rely on Systemd facilities.

Command line options:
```
-d: Enable debug mode
-h: Show help and exit
-t: Test database connection and exit
-v: Show version and exit
```
Note that logging is done almost entirely via syslog, facility user. Debug mode switches on concurrent logging to stderr.

### Reporting: `smtp-abuse-report.pl`.
The second part (script) is meant to generate reports by aggregating collected data, and send an appropriate email to the derived abuse contact address. It takes into account:
- New IP address entries since the last report has been sent — there might be duplicates to already reported ones,
- a one week penalty time for each contact address to not flood the responsible persons with complaint emails — not yet reported syslog entries stay eligible to be reported.

It also updates timestamps in the respective tables accordingly after a particular report has been sent. This should prevent reporting already reported entries. Dry run mode (`-n`) prevents writes to the database for testing purposes. However, a not existing database is created even in dry run mode.

Reports contain:
- Static text for the mailbody as shown above,
- the Abusix disclaimer as attachment,
- the actual tabular report as attachment, containing
   - timestamp according to the local time zone,
   - abusing IP address.

Dry run mode (`-n`) sends mails to the configured local sender's address instead of the database derived abuse contact. This primarily meant to see if reports make sense. Otherwise, reports are sent to the database derived abuse contact, and CC'ed to the configured local sender's address.

The local sender address is derived from the static string "abuse-report@", followed by the local domain name of the host. See line 33 of `smtp-abuse-report.pl`. Adjust as needed.

Sending mail utilizes the local MTA. You want to configure this properly prior.

Command line options:
```
-d: Enable debug mode
-h: Show help and exit
-n: "dry run" mode: don't update database, send mail to sender address
-t: Test database connection and exit
-v: Show version and exit
```
Note that logging is done almost entirely via syslog, facility user. Debug mode switches on concurrent logging to stderr.

Note that each run logs some statistics to syslog for easier observation that the script actually "does something".

#### Fallout.
Expect around 25% bounce messages for various reasons, such as:
- automatic "thank you for your email" replies, sometimes with a general (probably baseless) request for more information
- *out of office* replies
- automatic reply that the message won't be handled and one should undergo a manual process based on a web browser form to report abuse (probably violating RIR policy)
- generally underliverable messages for reasons such as
   - inbox over quota
   - user unknown (directly or expanded from distribution configuration)
   - administratively prohibited to receive mails
   - tagged as spam
   - badly configured redirects leading to SPF errors for the initial sending domain
   - non-existent domains

Currently, I'm manually evaluating these messages, in turn setting *contacts_report.lastreport* to `NULL` and provide an explanatory text in *contacts_report.comment*. I have not yet established a standard way how to deal with those. Overall, RIR policies demand abuse addresses to be functioning, and I'm planning to file complaints to the respective RIRs so they have their members fix their faulty abuse addresses.

An interesting category of automatic answers are from RIR abuse contacts. Looking more closely, these addresses are allegedly not managed by a given RIR despite the Abusix database listing the given RIR's abuse address for an IP address. I expect this to be an error of Abusix and will try to contact them to find a resolution.

## Installation.
I recommend cloning the repository to the home directory of a user who is allowed to read log files.

The local sender address is derived from the static string "abuse-report@", followed by the local domain name of the host. See line 33 of `smtp-abuse-report.pl`. Adjust as needed.

Sending mail utilizes the local MTA. You want to configure this properly now.

Next, install prerequisites. We use:
- DBI
- MIME::Lite
- Net::DNS

These are not part of the Perl standard modules, at least in Debian. Example for Debian 12:
```
apt-get install libdbd-sqlite3-perl libmime-lite-perl libnet-dns-perl
```
You can always just run `./smtp-abuse-syslog.pl`, or `./smtp-abuse-report.pl -n` to check for errors about missing perl modules. If there are no more, the former waits for data on stdin. Quit with EOF (`Ctrl-D`).

Next, use the archived logs to fill the database with inital data:
```
( zcat /var/log/mail.log.4.gz /var/log/mail.log.3.gz /var/log/mail.log.2.gz; cat /var/log/mail.log.1; ) |~/smtp-abuse-reporting/smtp-abuse-syslog.pl -d
```
Finally, create a cronjob like the following:
```
51 * * * *  /usr/sbin/logtail -f /var/log/mail.log -o .smtp-abuse-syslog-offset |smtp-abuse-reporting/smtp-abuse-syslog.pl
```
Because there is not yet a *~/.smtp-abuse-syslog-offset* file, the omitted current log file will be parsed entirely with the next cron run, and entries added accordingly. With that, there is no opportunity to miss any entries.

After testing with `-dn` as described above, you can add a daily cron job to actually send complaint emails accordingly.
```
53 8 * * *  smtp-abuse-reporting/smtp-abuse-report.pl
```

## Database layout.
The aforementioned `~/.abusedb.sqlite` is created automatically if it doesn't exist, and contains the following database tables and fields:
- **parsed_syslog** -- values derived from syslog lines
  - dnsptr -- PTR for the abusing IP address
  - ipaddr -- abusing IP address
  - logstamp -- timestamp from syslog
  - triedlogin -- login name which was attempted (currently filled but not used)
  - usestamp -- timestamp when this record was last used (reported); this is changed only by `smtp-abuse-report.pl`
- *parsed_syslog_idx* on logstamp, ipaddr, triedlogin for quicker SQL handling
- **contacts** -- individual abusing IP addresses with their respective abuse contact address
  - abuseaddr -- abuse contact address for a given IP address
  - ipaddr -- abusing IP address, see also table *parsed_syslog*
- *contacts_idx* on abuseaddr for quicker SQL handling
- **contacts_report** -- keeping track when a given abuse contact address received a report
  - abuseaddr -- abuse contact address, see also table *contacts*
  - lastreport -- timestamp when this particular contact last received a report
  - do_report -- default 1. If set to 0, no report should be sent to this particular address
  - comment -- should be used for notes regarding *do_report*, not used otherwise
- *contacts_report_idx* on lastreport, do_report for quicker SQL handling

*Contacts_report.do_report* is meant as a secondary measure to prevent bounces from abuse ignorant IP space users, besides manually reporting those to the respective RIR in charge.

Fields with common names but in distinct tables are meant to be used as a relation (SQL `JOIN`).

Fields designated as *not used* are not queried by the reporter script and are meant to provide more information to the user, or are reserved for future use.

## ToDos.
- Generate report with timestamps in UTC.
- How to handle feedback cases like "we informed customer, please be patient"?
- Expand report to show the number of abuses from a reported addres older than the two week "detailed" report
   - how to format this in the report?
- Modify cronjob to honor `smtp-abuse-syslog.pl` return level to backup/restore logtail's state file accordingly.
- Standard syslog format has no field for the current year. This **will** make the parser fail at year's turnaround, when suddenly after December January follows in the same log run. Should be worked around by a manual handler watching a transition from Month 12 to Month 1, in turn forcing `$year++`.
- Probably introduce a force-flag (`-f`) to the reporter script, making it ignore the lastreport penalty.
- Fix FIXME entries in the scripts.
- Format report according to xARF: https://docs.abusix.com/xarf/gV1jjx9ShyubpbCA4WmZKo
- Write a third script to provide meaningful statistics about the database content.

----

2024-03-25, poc@pocnet.net
