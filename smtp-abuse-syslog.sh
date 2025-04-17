#!/bin/sh

cp -a ${HOME}/.smtp-abuse-syslog-offset ${HOME}/.smtp-abuse-syslog-offset~

/usr/sbin/logtail -f /var/log/mail.log -o ${HOME}/.smtp-abuse-syslog-offset \
		|${HOME}/bin/smtp-abuse-syslog.pl || {
	echo "Error occurred, backing out offset-file."
	cp -a ${HOME}/.smtp-abuse-syslog-offset~ ${HOME}/.smtp-abuse-syslog-offset
}
