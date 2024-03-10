This is a collection of Perl scripts to automate the following workflow:
- filter out postfix syslog messages stating *authentication failure*,
- populate a SQLite table with the split information from the syslog messages,
- retrieve the abuse contact associated with a given IP address with DNS queries to the [Abusix  Abuse Contact DB](https://docs.abusix.com/abuse-contact-db/5BScLdS3SxHV1giQYpXpKm).

Note that I'm deliberately not using Systemd. The parser script relies on good old syslog log files, and `logtail` being used to feed just the added lines to it.

## Files.
- `smtp-abuse-syslog.pl` is the parser script which populates the found error messages into the SQLite database.

## Using.
Create a cronjob like the following:
```
51 * * * *  /usr/sbin/logtail -f /var/log/mail.log -o .smtp-abuse-syslog-offset |bin/smtp-abuse-syslog.pl
```
*Logtail* is part of the *logrotate* Package.

## ToDos.
- Finish the reporting part of this project.
- Standard syslog format has no field for the current year. This **will** make the parser fail at year's turnaround, when suddenly after December January follows in the same log run. What to do about this?

----

2024-03-10, poc@pocnet.net
