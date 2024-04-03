- Generate report with timestamps in UTC instead of local timezone.
- How to handle feedback cases like "we informed customer, please be patient"?
- Introduce a dynamically generated "Abuse Report ID" in email subject:
   - for easier association of sent reports with replies,
   - for documentation purposes (in the database),
   - for probable future automation (handling of incoming email).
- Reformat eventual email to not designate report as attached file. Some answers hint to people or automatisms not recognizing text attachments.
- Modify cronjob to honor `smtp-abuse-syslog.pl` return level to backup/restore logtail's state file accordingly.
- Probably add helper scripts to make updating database fields less laborious.
- Standard syslog format has no field for the current year. This **will** make the parser fail at year's turnaround, when suddenly after December January follows in the same log run. Should be worked around by a manual handler watching a transition from Month 12 to Month 1, in turn forcing `$year++`.
- Probably introduce a force-flag (`-f`) to `smtp-abuse-report.pl` script, making it ignore the lastreport penalty.
- Format report according to xARF: https://docs.abusix.com/xarf/gV1jjx9ShyubpbCA4WmZKo
- Write a third script to provide meaningful statistics about the database content.
- Add option to `smtp-abuse-report.pl` to force a complete report ignoring any time stamp restrictions, e. g. when a report should be re-sent after manually updating the contact address (*abuseaddr*):
   - by *abuseaddr* (`-a`),
   - by *ipaddr* (`-i`).

----

2024-04-03, poc@pocnet.net
