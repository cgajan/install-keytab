all: install-keytab push-keytab man

man:
	gzip -c install-keytab.1 >install-keytab.1.gz
	gzip -c install-keytab.conf.5 >install-keytab.conf.5.gz
	gzip -c push-keytab.1 >push-keytab.1.gz

install-keytab:
	gcc -l krb5 -l k5crypto -o install-keytab install-keytab.c

push-keytab:
	gcc -lssh -o push-keytab push-keytab.c

