- Generate report with timestamps in UTC instead of local timezone.
- How to handle feedback cases like "we informed customer, please be patient"?
- Probably introduce a force-flag (`-f`) to `smtp-abuse-report.pl` script, making it ignore the lastreport penalty.
- Format report according to xARF: https://docs.abusix.com/xarf/gV1jjx9ShyubpbCA4WmZKo
- Write a third script to provide meaningful statistics about the database content.
- Add option to `smtp-abuse-report.pl` to force a complete report ignoring any time stamp restrictions, e. g. when a report should be re-sent after manually updating the contact address (*abuseaddr*):
   - by *abuseaddr* (`-a`),
   - by *ipaddr* (`-i`).
- `smtp-abuse-report.pl`: Determine the number of mails **not** been sent because `do_report=0`.
- Currently, we assume abuse contact validity being indefinitely. This is wrong.
- Cleanup old entries?
- Another table with (local) networks to ignore erroneous login requests.

----

2025-04-17, poc@pocnet.net
