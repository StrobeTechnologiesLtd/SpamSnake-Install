#! /bin/sh
# +--------------------------------------------------------------------+
# SpamSnake Install Script
# +--------------------------------------------------------------------+
#
# Author - Robin Toy
# Contact - robin@strobe-it.co.uk
# Copyright (C) 2014  http://www.strobe-it.co.uk/
#
#
# This program is an internal script / command set designed to
# aid in the installation of SpamSnake.
# +--------------------------------------------------------------------+


# +---------------------------------------------------+
# Version Tracking
# +---------------------------------------------------+

date="09-01-2015"						# Last Updated On
version="1.1"							# Script Version
#binhome="/home/baruwa/px/bin/"			# Path to bin


# +---------------------------------------------------+
# Functions / Procedures List
# +---------------------------------------------------+
# menu_main()				This displays the choices a user can pick
# read_main()				This reads the choice from the main menu and calls the required procedure
# install_base ()			Function to install base OS packages using APT
# phase_1 ()				Phase 1 of setup that lunches many other functions in order
# phase_2 ()				Phase 2 of setup that lunches many other functions in order
# phase_3 ()				Phase 3 of setup that lunches many other functions in order
# fix_apt ()				Function to fix the problem with APT listing and installing packages
# install_webmin ()			Function to install Webmin
# install_dnsmasq ()		Function to install Dnsmasq
# install_mysql ()			Function to install MySQL
# install_postfix ()		Function to install Postfix
# install_filters ()		Function to install additional filters
# install_mailscanner ()	Function to install MailScanner
# install_spamassassin ()	Write - DCC enabling & spam.assassin.prefs.conf editing
# configure_mailscanner ()	Function that configures MailScanner
# install_baruwa ()			Write


# +---------------------------------------------------+
# Functions / Procedures
# +---------------------------------------------------+

# Fix Package List
#Error: Hash Sum Mismatch OR No Package Available to Install
function fix_apt () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	F I X  A P T   P A C K A G E   L I S T";
echo "------------------------------------------------------------------------------";

# **START** Fix APT list
echo "We are removing corrupt content from /var/lib/apt/lists directory";
echo "";
rm -fR /var/lib/apt/lists/*

echo "";
echo "We are now going to re-build the APT database";
apt-get update

echo "";
echo "Finished fixing APT";
sleep 8
# **END** Fix APT list
}

# Base OS Package Install
function install_base () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	B A S E   O S   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Base OS Packages
echo "We are now going to install the base packages for the OS."
echo ""
fix_apt
apt-get install binutils cpp fetchmail flex gcc libarchive-zip-perl libc6-dev libcompress-raw-zlib-perl libdb4.8-dev libpcre3 libpopt-dev lynx m4 make ncftp nmap openssl perl perl-modules unzip zip zlib1g-dev autoconf automake1.9 libtool bison autotools-dev g++ build-essential telnet wget gawk -y
echo ""
echo "Base packages installed."
sleep 8
# **END** Base OS Packages
}


# Webmin Package Install
function install_webmin () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	W E B M I N   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Webmin Install
echo "We are now going to install Webmin."
echo ""

cat >> /etc/apt/sources.list << EOF

#Webmin
deb http://download.webmin.com/download/repository sarge contrib
deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
EOF

wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
apt-get update
apt-get install webmin -y
echo ""
echo "Webmin package installed."
sleep 8
# **END** Webmin Install
}


# Dnsmasq Package Install
function install_dnsmasq () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	D N S M A S Q   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Dnsmasg Install
echo "We are now going to install Dnsmasq."
echo ""
apt-get install dnsmasq -y
sed -i "/^#listen-address=/ c\listen-address=127.0.0.1" /etc/dnsmasq.conf
echo ""
echo "Dnsmasq package installed."
sleep 8
# **END** Dnsmasq Install
}


# MySQL Package Install
function install_mysql () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	M Y S Q L   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** MySQL Install
echo "We are now going to install MySQL."
echo ""
apt-get install mysql-client mysql-server libdbd-mysql-perl -y
echo ""
echo "MySQL package installed."
sleep 8
# **END** MySQL Install
}


# Postfix Package Install
function install_postfix () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P O S T F I X   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install Postfix
echo "We are now going to install Postfix."
echo ""
apt-get install postfix postfix-mysql postfix-doc procmail -y
echo ""
echo "Postfix package installed"
sleep 2
# **END** Install Postfix

# **START** Configure Postfix
clear 2>/dev/null
echo "We are now going to configure Postfix."
postfix stop
sed -i "/^#smtp      inet  n       -       -       -       1       postscreen/ c\smtp      inet  n       -       -       -       1       postscreen" /etc/postfix/master.cf
sed -i "/^#smtpd     pass  -       -       -       -       -       smtpd/ c\smtpd     pass  -       -       -       -       -       smtpd" /etc/postfix/master.cf
sed -i "/^#dnsblog   unix  -       -       -       -       0       dnsblog/ c\dnsblog   unix  -       -       -       -       0       dnsblog" /etc/postfix/master.cf
sed -i "/^#tlsproxy  unix  -       -       -       -       0       tlsproxy/ c\tlsproxy  unix  -       -       -       -       0       tlsproxy" /etc/postfix/master.cf
sed -i "/^#smtps     inet  n       -       -       -       -       smtpd/ c\smtps     inet  n       -       -       -       -       smtpd" /etc/postfix/master.cf
sed -i "/pickup    fifo  n       -       -       60      1       pickup/ a\         -o content_filter=" /etc/postfix/master.cf
sed -i "/         -o content_filter=/ a\         -o receive_override_options=no_header_body_checks" /etc/postfix/master.cf

#Information for postfix.sh
clear 2>/dev/null
echo "Please enter the myorigin address (example: domain.tld)?"
read -p "myorigin: " MYORIGIN
echo ""
echo "Please enter the myhostname address (example: server1.domain.tld) ?"
read -p "myhostname: " MYHOSTNAME
echo ""
echo "What is the local IP range of the network (example: 192.168.1.0) ?"
read -p "IP Range: " MYNETWORKS
echo ""
echo "What is root email address (example: administrator@example.net) ?"
read -p "Root Email: " ROOTEMAIL
echo ""
echo "What is abuse email address (example: administrator@example.net) ?"
read -p "Abuse Email: " ABUSEEMAIL
echo ""
echo "What is postmaster email address (example: administrator@example.net) ?"
read -p "Postmaster Email: " POSTMASTEREMAIL
echo ""

# Replaces the old postfix.sh
postconf -e "alias_maps = hash:/etc/aliases"
newaliases
postconf -e "SnakeVer = 1.12.2.2" 
postconf -e "myorigin = ${MYORIGIN}"
postconf -e "myhostname = ${MYHOSTNAME}"
postconf -e "mynetworks = 127.0.0.0/8, ${MYNETWORKS}/24"
postconf -e "message_size_limit = 36700160"
postconf -e "local_transport = error:No local mail delivery"
postconf -e "mydestination = "
postconf -e "local_recipient_maps = "
postconf -e "relay_domains = mysql:/etc/postfix/mysql-relay_domains.cf"
postconf -e "relay_recipient_maps = mysql:/etc/postfix/mysql-relay_recipients.cf"
postconf -e "transport_maps = mysql:/etc/postfix/mysql-transports.cf"
postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual"
postconf -e "disable_vrfy_command = yes"
postconf -e "strict_rfc821_envelopes = no"
postconf -e "smtpd_banner = $myhostname ESMTP Strobe SpamSnake $SnakeVer"
postconf -e "smtpd_delay_reject = yes"
postconf -e "smtpd_recipient_limit = 100"
postconf -e "smtpd_helo_required = yes"
postconf -e "smtpd_client_restrictions = permit_sasl_authenticated, permit_mynetworks, permit"
postconf -e "smtpd_helo_restrictions = permit_sasl_authenticated, permit_mynetworks, permit"
postconf -e "smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender, reject_unknown_sender_domain, permit"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unknown_recipient_domain, reject_unauth_destination, whitelist_policy, grey_policy, check_policy_service unix:private/policy-spf, permit"
postconf -e "smtpd_data_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_pipelining"
postconf -e "smtpd_restriction_classes = grey_policy, whitelist_policy"
postconf –e "policy-spf_time_limit = 3600s"
postconf -e "grey_policy = check_policy_service unix:private/greyfix"
postconf -e "whitelist_policy = check_client_access mysql:/etc/postfix/mysql-global_whitelist.cf, check_sender_access mysql:/etc/postfix/mysql-global_whitelist.cf"
postconf -e "header_checks = regexp:/etc/postfix/header_checks"
postconf -e "postscreen_greet_action = enforce"
postconf -e "postscreen_access_list = permit_mynetworks"
postconf -e "postscreen_dnsbl_action = enforce"
postconf -e "postscreen_dnsbl_threshold = 2"
postconf -e "postscreen_dnsbl_sites = dul.dnsbl.sorbs.net"
postconf -e "#milter_default_action = accept"
postconf -e "#milter_protocol = 6"
postconf -e "#smtpd_milters = inet:localhost:9999"
postconf -e "#non_smtpd_milters = inet:localhost:9999"

touch /etc/postfix/virtual
echo "root ${ROOTEMAIL}" >> /etc/postfix/virtual && echo "abuse ${ABUSEEMAIL}" >> /etc/postfix/virtual && echo "postmaster ${POSTMASTEREMAIL}" >> /etc/postfix/virtual
postmap /etc/postfix/virtual

touch /etc/postfix/header_checks
echo "/^Received:/ HOLD" >> /etc/postfix/header_checks
postmap /etc/postfix/header_checks

cat > /etc/postfix/mysql-global_whitelist.cf <<EOF
#mysql-global_whitelist
user = baruwa
password = 5n@keSpam
dbname = baruwa
query = select concat('PERMIT') 'action' from lists where from_address='%s' AND list_type='1';
hosts = 127.0.0.1
EOF

cat > /etc/postfix/mysql-relay_domains.cf <<EOF
#mysql-relay_domains
user = baruwa
password = 5n@keSpam
dbname = baruwa
query = select concat(address, ' ', 'OK') 'domain' from user_addresses where user_addresses.address='%s' and user_addresses.enabled='1';
hosts = 127.0.0.1
EOF

cat > /etc/postfix/mysql-relay_recipients.cf <<EOF
#mysql-relay_recipients
user = baruwa
password = 5n@keSpam
dbname = baruwa
query = select concat('@', address, 'OK') 'email' from user_addresses where user_addresses.address='%d';
hosts = 127.0.0.1
EOF

cat > /etc/postfix/mysql-transports.cf <<EOF
#mysql-transports
user = baruwa
password = 5n@keSpam
dbname = baruwa
query = select concat('smtp:[', mail_hosts.address, ']', ':', port) 'transport' from mail_hosts, user_addresses where user_addresses.address = '%s' AND user_addresses.id = mail_hosts.useraddress_id;
hosts = 127.0.0.1
EOF
#finished postfix.sh

#sed '1 i\ SnakeVer = 1.12.2.2' /etc/postfix/main.cf
sed -i "/^smtpd_banner = / c\smtpd_banner = \$myhostname ESMTP Strobe SpamSnake \$SnakeVer" /etc/postfix/main.cf
postfix start
echo ""
echo "Configured Postfix"
echo ""
# **END** Configure Postfix

echo ""
echo "Postfix Install Finished."
sleep 8
}


# Mail Filter Install
function install_filters () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	M A I L   F I L T E R   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Mail Filter Install
echo "We are now going to install Filters."
echo ""

apt-get install razor pyzor clamav-daemon libclamav6 apparmor -y

echo ""
echo "Filters installed"
sleep 2
# **END** Mail Filter Install

# **START** Configure Apparmor
clear 2>/dev/null
echo "We are now going to configure Apparmor"
echo ""

usermod -a -G www-data clamav
sed -i "#clamav/ a\   /var/spool/MailScanner/** rw," /etc/apparmor.d/usr.sbin.clamd
sed -i "   /var/spool/MailScanner/** rw,/ a\   /var/spool/MailScanner/incoming/** rw," /etc/apparmor.d/usr.sbin.clamd
/etc/init.d/apparmor reload

echo ""
echo "Apparmor configured"
sleep 2
# **END** Configure Apparmor

# **START** Install DCC
clear 2>/dev/null
echo "We are going to configure DCC 32bit/64bit"

cd /tmp
wget http://ppa.launchpad.net/jonasped/ppa/ubuntu/pool/main/d/dcc/dcc-common_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
wget http://ppa.launchpad.net/jonasped/ppa/ubuntu/pool/main/d/dcc/dcc-client_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
dpkg -i dcc-common_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
dpkg -i dcc-client_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb

echo ""
echo "DCC 32bit/64bit configured"
sleep 2
# **END** Install DCC

# **START** Configure Pyzor
clear 2>/dev/null
echo "We are going to configure Pyzor"
echo ""

sed -i "/^#!/usr/bin/python/ c\#!/usr/bin/python -Wignore::DeprecationWarning" /usr/bin/pyzor
mkdir /var/lib/MailScanner
pyzor --homedir=/var/lib/MailScanner discover
pyzor ping

echo ""
echo "Pyzor configured"
sleep 2
# **END** Configure Pyzor

# **START** Configure Razor
clear 2>/dev/null
echo "We are going to configure Razor"
echo ""

rm /etc/razor/razor-agent.conf
mkdir /var/lib/MailScanner/.razor
razor-admin -home=/var/lib/MailScanner/.razor -create
razor-admin -home=/var/lib/MailScanner/.razor -discover
razor-admin -home=/var/lib/MailScanner/.razor -register
sed -i "/^debuglevel             = 3/ c\debuglevel             = 0" /var/lib/MailScanner/.razor/razor-agent.conf
sed -i "/^debuglevel             = 0/ a\razorhome              = /var/lib/MailScanner/.razor/" /var/lib/MailScanner/.razor/razor-agent.conf

echo ""
echo "Razor configured"
echo ""
# **END** Configure Razor

echo ""
echo "All Mail Filters Installed and Configured"
sleep 8
}


# MailScanner Package Install
function install_mailscanner () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	M A I L S C A N N E R   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** MailScanner Dependencies
echo "We are now going to install dependencies for MailScanner."
echo ""

apt-get install libconvert-tnef-perl libdbd-sqlite3-perl libfilesys-df-perl libmailtools-perl libmime-tools-perl libmime-perl libnet-cidr-perl libsys-syslog-perl libio-stringy-perl libfile-temp-perl libole-storage-lite-perl libarchive-zip-perl libsys-hostname-long-perl libnet-cidr-lite-perl libhtml-parser-perl libdb-file-lock-perl libnet-dns-perl libncurses5-dev libdigest-hmac-perl libnet-ip-perl liburi-perl libfile-spec-perl spamassassin libnet-ident-perl libmail-spf-perl libmail-dkim-perl dnsutils libio-socket-ssl-perl gdebi-core -y
wget http http://launchpadlibrarian.net/85191561/libdigest-sha1-perl_2.13-2build2_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
dpkg -i libdigest-sha1-perl_2.13-2build2_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb

echo ""
echo "Dependencies for MailScanner installed"
sleep 2
# **END** MailScanner Dependencies

# **START** Install MailScanner
clear 2>/dev/null
echo "We are now going to install MailScanner"

cd /usr/src
wget http://mailscanner.info/files/4/tar/MailScanner-install-4.84.6-1.tar.gz
tar xvfz MailScanner-install-4.84.6-1.tar.gz
cd MailScanner-install-4.84.6
./install.sh

echo ""
echo "MailScanner installed"
sleep 2
# **END** Install MailScanner

# **START** ClamAV Fix
clear 2>/dev/null
echo "Fix ClamAV Update script"
echo ""

sed -i "/^clamav/ c\clamav          /opt/MailScanner/lib/clamav-wrapper     /usr/" /opt/MailScanner/etc/virus.scanners.conf

echo ""
echo "ClamAV Update script fixed"
echo ""
# **END** ClamAV Fix

echo ""
echo "MailScanner Install Finished"
sleep 8
}


# Spamassassin Package Install
function install_spamassassin () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	S P A M A S S A S S I N   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** config backup
echo "We are doing a backup of the configuration files."
echo ""

mv /etc/spamassassin/local.cf /etc/spamassassin/local.cf.disabled
cp /opt/MailScanner/etc/spam.assassin.prefs.conf /opt/MailScanner/etc/spam.assassin.prefs.conf.back

echo ""
echo "Finished doing backup of the configuration files."
sleep 2
# **END** config backup

# **START** Enabled DCC
clear 2>/dev/null
echo "We are Enabling DCC Plugin."
echo ""

# commands for DCC

echo ""
echo "Finished Enabling DCC Plugin."
sleep 2
# **END** Enabled DCC

# **START** Create required folders
clear 2>/dev/null
echo "We are creating required folders."
echo ""

mkdir /var/www
mkdir /var/www/.spamassassin

echo ""
echo "Finished creating required folders."
sleep 2
# **END** Create required folders

# **START** Update Spamassassin configuration
clear 2>/dev/null
echo "We are updating Spamassassin configurations."
echo ""

# commands for y

echo ""
echo "Finished Spamassassin configurations."
sleep 2
# **END** Update Spamassassin configuration

# **START** setting required permissions
clear 2>/dev/null
echo "We are setting the required permissions on folders."
echo ""

chown -R postfix:www-data /var/spool/postfix/hold
chmod -R ug+rwx /var/spool/postfix/hold

echo ""
echo "Finished setting the required permissions on folders."
sleep 2
# **END** setting required permissions

# **START** information about MySQL and Perl MCPAN
clear 2>/dev/null
echo "Please now read the documentation about creating the"
echo "MySQL data base and importing the base structure."
echo "Once this has been done please install the perl addins"
echo "using the MCPAN instructions."
echo ""
sleep 8
# **END** information about MySQL and Perl MCPAN

echo ""
echo "Spamassassin configured."
sleep 8
}


# MailScanner Package Configuration #NEEDS FIXING
function configure_mailscanner () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	M A I L S C A N N E R   P A C K A G E   C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";

# **START** Config Backup
echo "We are now going to prepare folders and back configuration files."
echo ""

mkdir /var/spool/MailScanner/spamassassin
cp /opt/MailScanner/etc/MailScanner.conf /opt/MailScanner/etc/MailScanner.conf.dist
cp /opt/MailScanner/etc/spam.lists.conf /opt/MailScanner/etc/spam.lists.conf.dist

echo ""
echo "Configured folders and created required backups"
sleep 2
# **END** Config Backup

# **START** Configure MailScanner
clear 2>/dev/null
echo "We are now going to configure MailScanner"

#Information for mailscanner.sh
echo "Please enter the org-name (example: STROBE-IT-CO-UK)"
read -p "orgname: " ORGNAME
echo ""
echo "Please enter the org-long-name (example: Strobe Technologies Ltd)"
read -p "longorgname: " LONGORGNAME
echo ""
echo "What is the website address of the company (example: www.strobe-it.co.uk) ?"
read -p "website: " WEBSITE
echo ""

# Replaces the old mailscanner.sh
sed -i "/^%org-name% =/ c\%org-name% =\${ORGNAME}" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^%org-long-name% =/ c\%org-long-name% = \${LONGORGNAME}" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^%web-site% =/ c\%web-site% = \${WEBSITE}" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Run As User =/ c\Run As User = postfix" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Run As Group =/ c\Run As Group = www-data" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Incoming Work Group =/ c\Incoming Work Group = clamav" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Incoming Work Permissions =/ c\Incoming Work Permissions = 0640" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Incoming Queue Dir =/ c\Incoming Queue Dir = /var/spool/postfix/hold" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Outgoing Queue Dir =/ c\Outgoing Queue Dir = /var/spool/postfix/incoming" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^MTA =/ c\MTA = postfix" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Quarantine User =/ c\Quarantine User = root" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Quarantine Group =/ c\Quarantine Group = www-data" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Quarantine Permissions =/ c\Quarantine Permissions = 0660" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Quarantine Whole Message =/ c\Quarantine Whole Message = yes" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Virus Scanners =/ c\Virus Scanners = clamd" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Monitors for ClamAV Updates =/ c\Monitors for ClamAV Updates = /var/lib/clamav/*.cld /var/lib/clamav/*.cvd" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Clamd Socket =/ c\Clamd Socket = /var/run/clamav/clamd.ctl" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Clamd Lock File =/ c\Clamd Lock File = /var/run/clamav/clamd.pid" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Subject Text =/ c\Spam Subject Text = ***SPAM***" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Actions =/ c\Spam Actions = deliver store" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^High Scoring Spam Actions =/ c\High Scoring Spam Actions = store delete" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Non Spam Actions =/ c\Non Spam Actions = deliver store" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^SpamAssassin User State Dir =/ c\SpamAssassin User State Dir = /var/spool/MailScanner/spamassassin" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Deliver Unparsable TNEF =/ c\Deliver Unparsable TNEF = yes" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^TNEF Expander  =/ c\TNEF Expander  = internal" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam-Virus Header = X-%org-name%-MailScanner-SpamVirus-Report:/ c\Spam-Virus Header = X-%org-name%-SpamSnake-SpamVirus-Report:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Mail Header =/ c\Mail Header = X-%org-name%-SpamSnake:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Header =/ c\Spam Header = X-%org-name%-SpamSnake-SpamCheck:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Score Header =/ c\Spam Score Header = X-%org-name%-SpamSnake-SpamScore:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Information Header =/ c\Information Header = X-%org-name%-SpamSnake-Information:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Envelope From Header =/ c\Envelope From Header = X-%org-name%-SpamSnake-From:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Envelope To Header =/ c\Envelope To Header = X-%org-name%-SpamSnake-To:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^ID Header =/ c\ID Header = X-%org-name%-SpamSnake-ID:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^IP Protocol Version Header =/ c\IP Protocol Version Header = # X-%org-name%-SpamSnake-IP-Protocol:" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Hostname =/ c\Hostname = the %org-name% ($HOSTNAME) SpamSnake" /opt/MailScanner/etc/MailScanner.conf
#sed -i "/^Notice Signature =/ c\Notice Signature = -- \\nSpamSnake\\nEmail Virus Scanner\\nsecurity.strobe-it.co.uk" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Notices From =/ c\Notices From = SpamSnake" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam List Definitions =/ c\Spam List Definitions = %etc-dir%/spam.lists.conf" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Checks =/ c\Spam Checks = yes" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam List =/ c\Spam List = spamcop.net PSBL spamhaus-ZEN SORBS-HTTP SORBS-SOCKS SORBS-MISC SORBS-SMTP SORBS-WEB SORBS-BLOCK SORBS-ZOMBIE SORBS-DUL SORBS-RHSBL" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Spam Domain List =/ c\Spam Domain List = SORBS-BADCONF SORBS-NOMAIL" /opt/MailScanner/etc/MailScanner.conf
sed -i "/^Watermark Header =/ c\Watermark Header = X-%org-name%-SpamSnake-Watermark:" /opt/MailScanner/etc/MailScanner.conf
# finish mailscanner.sh

echo ""
echo "MailScanner configured"
sleep 2
# **END** Configure MailScanner

# **START** Creating RBL List
clear 2>/dev/null
echo "Create RBL List"
echo ""

cat > /opt/MailScanner/etc/spam.lists.conf <<EOF
## Strobe Technologies Ltd
## -----------------------
## MX / Spam filter
## MailScanner spam.lists.conf
## -----------------------
## Version: V1.0
## -----------------------
## -----------------------

## SPAM Lists
spamhaus.org			sbl.spamhaus.org.		# Not used as included in ZEN
spamhaus-XBL			xbl.spamhaus.org.		# Not used as included in ZEN
spamhaus-PBL			pbl.spamhaus.org.		# Not used as included in ZEN
spamhaus-ZEN			zen.spamhaus.org.
SBL+XBL					sbl-xbl.spamhaus.org.	# Not used as included in ZEN
spamcop.net				bl.spamcop.net.
PSBL					psbl.surriel.com.
SORBS-DNSBL             dnsbl.sorbs.net.
SORBS-HTTP              http.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-SOCKS             socks.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-MISC              misc.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-SMTP              smtp.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-WEB               web.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-SPAM              spam.dnsbl.sorbs.net.	# Not used as too aggressive
SORBS-BLOCK             block.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-ZOMBIE            zombie.dnsbl.sorbs.net.	# Not used as included in DNSBL
SORBS-DUL               dul.dnsbl.sorbs.net.	# Used by PostScreen in SMTP tests
SORBS-RHSBL             rhsbl.sorbs.net.		# Not used as included in DNSBL


## SPAM Domain List
SORBS-BADCONF			badconf.rhsbl.sorbs.net.
SORBS-NOMAIL			nomail.rhsbl.sorbs.net.

EOF

echo ""
echo "RBL List Created"
sleep 2
# **END** Creating RBL List

# **START** MailScanner Startup Script   ---- ISSUES with this
clear 2>/dev/null
echo "Create MailScanner Startup Script"
echo ""

#----- This is where the issues are...
cat > /etc/init.d/mailscanner <<EOF
#! /bin/sh
   ### BEGIN INIT INFO
   # Provides:          MailScanner daemon
   # Required-Start:    $local_fs $remote_fs
   # Required-Stop:     $local_fs $remote_fs
   # Default-Start:     2 3 4 5
   # Default-Stop:      0 1 6
   # Short-Description: Controls mailscanner instances
   # Description:       MailScanner is a queue-based spam/virus filter
   ### END INIT INFO
   # Author: Simon Walter <simon.walter@hp-factory.de>
   # PATH should only include /usr/* if it runs after the mountnfs.sh script
   PATH=/usr/sbin:/usr/bin:/bin:/sbin:/opt/MailScanner/bin
   DESC="mail spam/virus scanner"
   NAME=MailScanner
   PNAME=mailscanner
   DAEMON=/opt/MailScanner/bin/$NAME
   STARTAS=MailScanner
   SCRIPTNAME=/etc/init.d/$PNAME
   CONFFILE=/opt/MailScanner/etc/MailScanner.conf
   # Exit if the package is not installed
   [ -x "$DAEMON" ] || exit 0
   run_nice=0
   stopped_lockfile=/var/lock/subsys/MailScanner.off
   # Read configuration variable file if it is present
   [ -r /etc/default/$PNAME ] && . /etc/default/$PNAME
   # Load the VERBOSE setting and other rcS variables
   . /lib/init/vars.sh
   # Define LSB log_* functions.
   # Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
   . /lib/lsb/init-functions
   # sanity check for permissions
   fail()
   {
   echo >&2 "$0: $1"
   exit 1
   }
   check_dir()
   {
   if [ ! -d $1 ]; then
   mkdir -p "$1" || \
   fail "directory $1: does not exist and cannot be created"
   fi
   actual="$(stat -c %U $1)"
   if [ "$actual" != "$2" ]; then
   chown -R "$2" "$1" || \
   fail "directory $1: wrong owner (expected $2 but is $actual)"
   fi
   actual="$(stat -c %G $1)"
   if [ "$actual" != "$3" ]; then
   chgrp -R "$3" "$1" || \
   fail "directory $1: wrong group (expected $3 but is $actual)"
   fi
   }
   user=$(echo $(awk -F= '/^Run As User/ {print $2; exit}' $CONFFILE))
   group=$(echo $(awk -F= '/^Run As Group/ {print $2; exit}' $CONFFILE))
   check_dir /var/spool/MailScanner       ${user:-postfix} ${group:-www-data}
   check_dir /var/lib/MailScanner         ${user:-postfix} ${group:-www-data}
   check_dir /var/run/MailScanner         ${user:-postfix} ${group:-www-data}
   check_dir /var/lock/subsys	${user:-root}	${group:-root} #Required to Create Folder
   check_dir /var/lock/subsys/MailScanner ${user:-postfix} ${group:-www-data}
   #
   # Function that starts the daemon/service
   #
   do_start()
   {
   # Return
   #   0 if daemon has been started
   #   1 if daemon was already running
   #   2 if daemon could not be started
   start-stop-daemon --start --quiet --startas $STARTAS --name $NAME --test > /dev/null \
   || return 1
   start-stop-daemon --start --quiet --nicelevel $run_nice --chuid postfix:www-data --exec $DAEMON --name $NAME -- $DAEMON_ARGS \
   || return 2
   # Add code here, if necessary, that waits for the process to be ready
   # to handle requests from services started subsequently which depend
   # on this one.  As a last resort, sleep for some time.
   # Set lockfile to inform cronjobs about the running daemon
   RETVAL="$?"
   if [ $RETVAL -eq 0 ]; then
   touch /var/lock/subsys/mailscanner
   rm -f $stopped_lockfile
   fi
   if [ $RETVAL -eq 0 ]; then
   echo "MailScanner Started"
   fi
   }
   #
   # Function that stops the daemon/service
   #
   do_stop()
   {
   # Return
   #   0 if daemon has been stopped
   #   1 if daemon was already stopped
   #   2 if daemon could not be stopped
   #   other if a failure occurred
   start-stop-daemon --stop --retry=TERM/30 --name $NAME
   RETVAL="$?"
   [ "$RETVAL" = 2 ] && return 2
   # Remove lockfile for cronjobs
   if [ $RETVAL -eq 0 ]; then
   rm -f /var/lock/subsys/mailscanner
   touch $stopped_lockfile
   fi
   if [ $RETVAL -eq 0 ]; then
   echo "MailScanner Stopped"
   fi
   }
   #
   # Function that sends a SIGHUP to the daemon/service
   #
   do_reload() {
   start-stop-daemon --stop --signal 1 --quiet --name $NAME
   return 0
   }
   case "$1" in
   start)
   [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
   do_start
   case "$?" in
   0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
   2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
   esac
   ;;
   stop)
   [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
   do_stop
   case "$?" in
   0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
   2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
   esac
   ;;
   restart|force-reload)
   #
   # If the "reload" option is implemented then remove the
   # 'force-reload' alias
   #
   log_daemon_msg "Restarting $DESC" "$NAME"
   do_stop
   case "$?" in
   0|1)
   do_start
   case "$?" in
   0) log_end_msg 0 ;;
   1) log_end_msg 1 ;; # Old process is still running
   *) log_end_msg 1 ;; # Failed to start
   esac
   ;;
   *)
   # Failed to stop
   log_end_msg 1
   ;;
   esac
   ;;
   *)
   echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload}" >&2
   exit 3
   ;;
   esac
 exit 0

EOF

chmod +x /etc/init.d/mailscanner
chmod 755 /etc/init.d/mailscanner
update-rc.d mailscanner defaults
ln -s /opt/MailScanner/bin/Quick.Peek /usr/sbin/Quick.Peek
/etc/init.d/postfix stop
/etc/init.d/mailscanner start
/etc/init.d/postfix start

echo ""
echo "Created MailScanner Startup Script"
echo ""
# **END** MailScanner Startup Script

echo ""
echo "MailScanner Configuration Finished"
sleep 8
}


# Spamassassin Package Install
function install_baruwa () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	B A R U W A   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** MailScanner Symlinks
echo "We are creating symlinks for MailScanner."
echo ""

ln -s /opt/MailScanner/etc /etc/MailScanner
ln -s /opt/MailScanner/lib/MailScanner/CustomFunctions /etc/MailScanner

echo ""
echo "Finished creating symlinks."
sleep 2
# **END** MailScanner Symlinks

# **START** Install RabbitMQ
clear 2>/dev/null
echo "Installing RabbitMQ."
echo ""

cat >> /etc/apt/sources.list << EOF

#RabbitMQ
deb http://www.rabbitmq.com/debian/ testing main
EOF

wget http://www.rabbitmq.com/rabbitmq-signing-key-public.asc
apt-key add rabbitmq-signing-key-public.asc
apt-get update
apt-get install rabbitmq-server -y

rabbitmqctl add_user baruwa password
rabbitmqctl add_vhost baruwa
rabbitmqctl set_permissions -p baruwa baruwa ".*" ".*" ".*"
rabbitmqctl delete_user guest

/etc/init.d/rabbitmq-server restart

echo ""
echo "Finished installing RabbitMQ."
sleep 2
# **END** Install RabbitMQ

# **START** Install Baruwa
clear 2>/dev/null
echo "We are installing Baruwa."
echo ""

wget -O - http://apt.baruwa.org/baruwa-apt-keys.gpg | apt-key add -

cat >> /etc/apt/sources.list << EOF

#baruwa
deb http://apt.baruwa.org/ubuntu precise main
EOF

apt-get update
apt-get install python-django-celery python-importlib -y
mkdir /usr/src/baruwa1124
cd /usr/src/baruwa1124

wget https://docs.google.com/uc?id=0B9cN15Q3pKnwLW1WNG9rN0dQNzg&export=download&hl=en
mv uc?id=0B9cN15Q3pKnwLW1WNG9rN0dQNzg baruwa_1.1.2-4sn_all.deb
wget https://docs.google.com/uc?id=0B9cN15Q3pKnwMHFUMFhWMW4ycU0&export=download&hl=en
mv uc?id=0B9cN15Q3pKnwMHFUMFhWMW4ycU0 baruwa-doc_1.1.2-4sn_all.deb

gdebi baruwa_1.1.2-4sn_all.deb
gdebi baruwa-doc_1.1.2-4sn_all.deb

rm -r /usr/share/pyshared/baruwa/settings.py
ln -s /etc/baruwa/settings.py /usr/share/pyshared/baruwa/

echo ""
echo "Finished installing Baruwa."
sleep 2
# **END** Install Baruwa

# **START** Adding Additional Settings to Baruwa
clear 2>/dev/null
echo "We are doing Adding Additional Settings to Baruwa."
echo ""

echo "What is the URL to access your spam filter (example: http://spam.strobe-it.co.uk) ?"
read -p "Spam URL: " SPAMURL
echo ""
echo "What is your Time Zone (example: Europe/London) ?"
read -p "Time Zone: " TIMEZONE
echo ""
echo "What is the email address your spam report will be sent from (example: SpamSnake@strobe-it.co.uk) ?"
read -p "Spam Report Email: " SPAMREPORTEMAIL
echo ""

sed -i "/^QUARANTINE_REPORT_HOSTURL =/ c\QUARANTINE_REPORT_HOSTURL = '\${SPAMURL}'" /etc/baruwa/settings.py
sed -i "/^TIME_ZONE =/ c\TIME_ZONE = '\${TIMEZONE}'" /etc/baruwa/settings.py
sed -i "/^#DEFAULT_FROM_EMAIL =/ c\DEFAULT_FROM_EMAIL = '\${SPAMREPORTEMAIL}'" /etc/baruwa/settings.py

baruwa-admin syncdb --noinput
baruwa-admin migrate baruwa.fixups
baruwa-admin migrate baruwa.accounts
baruwa-admin migrate baruwa.messages
baruwa-admin migrate baruwa.lists
baruwa-admin migrate baruwa.reports
baruwa-admin migrate baruwa.status
baruwa-admin migrate baruwa.config

sed -i "/^Run As Group =/ c\Run As Group = celeryd" /etc/MailScanner/MailScanner.conf
sed -i "/^Quarantine User =/ c\Quarantine User = celery" /etc/MailScanner/MailScanner.conf
sed -i "/^Quarantine Group =/ c\Quarantine Group = celery" /etc/MailScanner/MailScanner.conf
sed -i "/^Is Definitely Not Spam =/ c\Is Definitely Not Spam = &BaruwaWhitelist" /etc/MailScanner/MailScanner.conf
sed -i "/^Is Definitely Spam =/ c\Is Definitely Spam = &BaruwaBlacklist" /etc/MailScanner/MailScanner.conf
sed -i "/^Required SpamAssassin Score =/ c\Required SpamAssassin Score = &BaruwaLowScore" /etc/MailScanner/MailScanner.conf
sed -i "/^High SpamAssassin Score =/ c\High SpamAssassin Score = &BaruwaHighScore" /etc/MailScanner/MailScanner.conf
sed -i "/^Always Looked Up Last =/ c\Always Looked Up Last = &BaruwaSQL" /etc/MailScanner/MailScanner.conf
sed -i "/^Quarantine User =/ c\Quarantine User = celeryd" /opt/MailScanner/etc/conf.d/baruwa.conf
sed -i "/^Inline HTML Signature =/ c\#Inline HTML Signature = htmlsigs.customize" /opt/MailScanner/etc/conf.d/baruwa.conf
sed -i "/^Inline Text Signature =/ c\#Inline Text Signature = textsigs.customize" /opt/MailScanner/etc/conf.d/baruwa.conf
sed -i "/^Signature Image Filename =/ c\#Signature Image Filename = sigimgfiles.customize" /opt/MailScanner/etc/conf.d/baruwa.conf
sed -i "/^Signature Image <img> Filename =/ c\#Signature Image <img> Filename = sigimgs.customize" /opt/MailScanner/etc/conf.d/baruwa.conf

usermod -a -G celeryd clamav
chgrp -R celeryd /var/spool/MailScanner/quarantine

echo ""
echo "Finished doing Adding Additional Settings to Baruwa."
echo ""
# **END** Adding Additional Settings to Baruwa

echo ""
echo "Baruwa Installed."
sleep 8
}


# Launch Advanced Menu
function launch_advanced () {
clear 2>/dev/null
advmenu="1"
while [ $advmenu == "1" ]
	do
		menu_advanced
		read_advanced
	done
}




# +---------------------------------------------------+
# Install Phase
# +---------------------------------------------------+

# Phase 1
function phase_1 () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   1";
echo "------------------------------------------------------------------------------";

fix_apt
install_webmin
install_dnsmasq
install_mysql
install_postfix
install_filters
install_mailscanner

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   1";
echo "------------------------------------------------------------------------------";
echo "";
echo "Please restart the Linux box and continue to Phase 2";

sleep 8
}


# Phase 2
function phase_2 () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   2";
echo "------------------------------------------------------------------------------";

install_spamassassin

sleep 8
}


# Phase 3
function phase_3 () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   3";
echo "------------------------------------------------------------------------------";

configure_mailscanner
install_baruwa

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   3";
echo "------------------------------------------------------------------------------";
echo "";
echo "Please restart the Linux box and continue to Phase 4";

sleep 8
}

# Phase 4
function phase_4 () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   4";
echo "------------------------------------------------------------------------------";

#configure_mailscanner
#install_baruwa

sleep 8
}




# +---------------------------------------------------+
# Display menus
# +---------------------------------------------------+

menu_main() {
	clear
	echo "------------------------------"
	echo "SpamSnake Install"
	echo ""
	echo "Please make a choice:"
	echo ""
	echo "a) Install Base OS Packages"
	echo "b) Phase 1 Setup"
	echo "c) Phase 2 Setup"
	echo "d) Phase 3 Setup"
	echo "e) Phase 4 Setup"
	#echo "f) Phase 5 Setup"
	#echo "g) Send Whitelist Data"
	#echo "f) Update SpamAssassin Rules"
	#echo "g) Update Search Index"
	#echo "h) Clean Quarantine"
	#echo "i) Clean Database"
	echo "z) Advanced Install"
	echo " "
	echo "x) Exit"
}


menu_advanced() {
	clear
	echo "------------------------------"
	echo "SpamSnake Advanced Install"
	echo ""
	echo "Please make a choice:"
	echo ""
	echo "a) Install Base OS Packages"
	echo "b) Install Webmin"
	echo "c) Install Dnsmasq"
	echo "d) Install MySQL"
	echo "e) Install Postfix"
	echo "f) Install Mail Filters"
	echo "g) Install MailScanner"
	echo "h) Install Spamassassin"
	echo "i) Configure MailScanner"
	echo "j) Install Baruwa"
	echo " "
	echo "y) Fix APT"
	echo " "
	echo " "
	echo "x) Exit"
}




# +---------------------------------------------------+
# Choices
# +---------------------------------------------------+

read_main() {
	local choice
	read -p "Enter Choice: " choice
	case $choice in
		a) install_base ;;
		b) phase_1 ;;
		c) phase_2 ;;
		d) phase_3 ;;
		e) phase_4 ;;
		f) phase_5 ;;
		g) update_search_index ;;
		z) launch_advanced ;;
		x) exit 0 ;;
		*) echo -e "Error \"$choice\" is not an option..." && sleep 2
	esac
}


read_advanced() {
	local choice
	read -p "Enter Choice: " choice
	case $choice in
		a) install_base ;;
		b) install_webmin ;;
		c) install_dnsmasq ;;
		d) install_mysql ;;
		e) install_postfix ;;
		f) install_filters ;;
		g) install_mailscanner ;;
		h) install_spamassassin ;;
		i) configure_mailscanner ;;
		j) install_baruwa ;;
		y) fix_apt ;;
		x) exit 0 ;;
		*) echo -e "Error \"$choice\" is not an option..." && sleep 2
	esac
}




# +---------------------------------------------------+
# Be sure we're root
# +---------------------------------------------------+

if [ `whoami` == root ]
	then
		menu="1"
		while [ $menu == "1" ]
		do
			menu_main
			read_main
		done
	else
		echo "Sorry, but you are not root."
		echo "Please su or sudo - then try again."
		exit 0
	fi
# +---------------------------------------------------+