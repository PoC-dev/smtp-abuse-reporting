#!/bin/sh

# Readable only for us.
umask 077

printf ".mode csv\n.nullvalue NULL\n.headers off\nSELECT triedlogin, dnsptr, ipaddr, logstamp, reported, report_id FROM parsed_syslog;\n.quit\n" |sqlite3 -batch ~/.abusedb.sqlite |tr -d '\r' |sed -E \
	-e 's/"([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(\.000)?"/\1-\2.\3.\4.000000/g' \
	-e 's/NULL//g' > /tmp/parsed_syslog.csv
printf ".mode csv\n.nullvalue NULL\n.headers off\nSELECT ipaddr, abuseaddr, allegedfix, comment FROM contacts;\n.quit\n" |sqlite3 -batch ~/.abusedb.sqlite |tr -d '\r' |sed -E \
	-e 's/"([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(\.000)?"/\1-\2.\3.\4.000000/g' \
	-e 's/NULL//g' > /tmp/contacts.csv
printf ".mode csv\n.nullvalue NULL\n.headers off\nSELECT abuseaddr, do_report, comment, lastreport, report_id FROM contacts_report;\n.quit\n" |sqlite3 -batch ~/.abusedb.sqlite |tr -d '\r' |sed -E \
	-e 's/"([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(\.000)?"/\1-\2.\3.\4.000000/g' \
	-e 's/NULL//g' -e 's/""/"/g' > /tmp/contacts_report.csv
