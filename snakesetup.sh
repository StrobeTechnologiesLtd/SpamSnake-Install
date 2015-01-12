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

date="12-01-2015"						# Last Updated On
version="1.3"							# Script Version
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
# phase_4 ()				Phase 4 of setup that lunches many other functions in order
# phase_5 ()				Phase 5 of setup that lunches many other functions in order
# fix_apt ()				Function to fix the problem with APT listing and installing packages
# install_webmin ()			Function to install Webmin
# install_dnsmasq ()		Function to install Dnsmasq
# install_mysql ()			Function to install MySQL
# install_postfix ()		Function to install Postfix
# install_filters ()		Function to install additional filters
# install_mailscanner ()	Function to install MailScanner
# install_spamassassin ()	Write - DCC enabling & spam.assassin.prefs.conf editing
# configure_mailscanner ()	Function that configures MailScanner
# install_baruwa ()			Function that installs and configures Baruwa
# install_baruwaweb ()		Function that installs the web servers and configures them for Baruwa


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


# Baruwa Package Install
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


# Baruwa Webserver Install
function install_baruwaweb () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	B A R U W A   W E B S E R V E R   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

apt-get install nginx-full uwsgi uwsgi-plugin-python -y

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Create config files
echo "We are creating config files."
echo ""

cat >> /etc/uwsgi/apps-available/baruwa.ini << EOF
[uwsgi]
workers = 2
chdir = /usr/share/pyshared/baruwa
env = DJANGO_SETTINGS_MODULE=baruwa.settings
module = django.core.handlers.wsgi:WSGIHandler()
EOF

echo "What is your external server name (example: spam.strobe-it.co.uk) ?"
read -p "External Server Name: " SERVERNAME
echo ""
cat >> /etc/nginx/sites-available/baruwa.conf << EOF
server {
listen 80;
server_name ${SERVERNAME};
root /usr/share/pyshared/baruwa;
autoindex on;
access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log;
location /static {
    root /usr/share/pyshared/baruwa/static/;
    }
    # static resources
    location ~* ^.+\.(html|jpg|jpeg|gif|png|ico|css|zip|tgz|gz|rar|bz2|doc|xls|exe|pdf|ppt|txt|tar|mid|midi|wav|bmp|rtf|js)$
    {
      expires 30d;
      break;
    }
location / {
    uwsgi_pass unix:///var/run/uwsgi/app/baruwa/socket;
    include uwsgi_params;
    }
}
EOF

echo ""
echo "Finished creating config files."
sleep 2
# **END** Create config files

# **START** Create Symlinks
echo "We are creating all symlinks."
echo ""

ln -s /etc/nginx/sites-available/baruwa.conf /etc/nginx/sites-enabled/baruwa.conf
ln -s /etc/uwsgi/apps-available/baruwa.ini /etc/uwsgi/apps-enabled/baruwa.ini
rm -r /etc/nginx/sites-enabled/default
cp /usr/share/doc/uwsgi-extra/nginx/uwsgi_params /etc/nginx/uwsgi_params

/etc/init.d/uwsgi restart
/etc/init.d/nginx restart

ln -s /usr/share/pyshared/baruwa/manage.py /usr/bin/manage.py
chmod +x /usr/bin/manage.py

/etc/init.d/mailscanner stop
/etc/init.d/mailscanner start


echo ""
echo "Finished creating all symlinks."
sleep 2
# **END** Create Symlinks

echo ""
echo "Baruwa Webserver Installed."
sleep 8
}


# SPF Package Install
function install_SPF () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	S P F   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

apt-get install postfix-policyd-spf-python -y

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Configure Postfix to use SPF
echo "We are configuring Postfix"
echo ""

cat >> /etc/postfix/master.cf <<EOF

policy-spf  unix  -       n       n       -       -       spawn      
   user=nobody argv=/usr/bin/policyd-spf
EOF

/etc/init.d/postfix restart

echo ""
echo "Finished configuring Postfix."
sleep 2
# **END** Configure Postfix to use SPF

echo ""
echo "SPF Package Installed."
sleep 8
}


# FuzzyOCR Package Install #NEED to Download MYSQL Script
function install_fuzzyocr () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	F U Z Z Y O C R   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

apt-get install fuzzyocr netpbm gifsicle libungif-bin gocr ocrad libstring-approx-perl libmldbm-sync-perl libdigest-md5-perl libdbd-mysql-perl imagemagick tesseract-ocr -y

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Download and Configure FuzzOCR
echo "We are Downloading and Configuring FuzzyOCR"
echo ""

wget http://users.own-hero.net/~decoder/fuzzyocr/fuzzyocr-3.6.0.tar.gz
tar xvfz fuzzyocr-3.6.0.tar.gz && cd FuzzyOcr-3.6.0/

sed -i "/^#focr_global_wordlist/ c\focr_global_wordlist /etc/spamassassin/FuzzyOcr.words" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_preprocessor_file/ c\focr_preprocessor_file /etc/spamassassin/FuzzyOcr.preps" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_scanset_file/ c\focr_scanset_file /etc/spamassassin/FuzzyOcr.scansets" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_enable_image_hashing/ c\focr_enable_image_hashing 3" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_digest_db/ c\focr_digest_db /etc/spamassassin/FuzzyOcr.hashdb" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_db_hash/ c\focr_db_hash /etc/spamassassin/FuzzyOcr.db" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_db_safe/ c\focr_db_safe /etc/spamassassin/FuzzyOcr.safe.db" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_bin_helper convert/ c\focr_bin_helper convert, tesseract" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^focr_path_bin/ c\#focr_path_bin /usr/local/netpbm/bin:/usr/local/bin:/usr/bin" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_db/ c\focr_mysql_db FuzzyOcr" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_hash/ c\focr_mysql_hash Hash" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_safe/ c\focr_mysql_safe Safe" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_user/ c\focr_mysql_user fuzzyocr" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_pass/ c\focr_mysql_pass fuzzyocr" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_host/ c\focr_mysql_host localhost" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_port/ c\focr_mysql_port 3306" /etc/spamassassin/FuzzyOcr.cf
sed -i "/^#focr_mysql_socket/ c\focr_mysql_socket /var/run/mysqld/mysqld.sock" /etc/spamassassin/FuzzyOcr.cf

cat > /usr/sbin/fuzzy-cleanmysql <<EOF
#!/usr/bin/perl
#Script to clean out mysql tables of data. Default is to leave data in Safe for 1 day and Hash for 10 days.
#Fuzzyocr-cleanmysql
use Getopt::Long;
use DBI;
use MLDBM qw(DB_File Storable);
my %Files = (
    db_hash => '/var/lib/fuzzyocr/FuzzyOcr.db',
    db_safe => '/var/lib/fuzzyocr/FuzzyOcr.safe.db',
    );
use DBI;
$database = "FuzzyOcr";
$hostname = "localhost";
$socket = "/var/run/mysqld/mysqld.sock";
$port = "3306";
$username = "fuzzyocr";
$password = 'password';
# defaults
my $cfgfile = "/etc/spamassassin/FuzzyOcr.cf";
my %App;
my %age;
$age{'age'} = 10*24;  # 10 days
$age{'hash'} = $age{'age'};
$age{'safe'} = 0;
my $help = 0;
my $verbose = 0;
GetOptions( \%age,
    'age=i',
    'config=s' => \$cfgfile,
    'hash=i',
    'help' => \$help,
    'safe=i',
    'verbose' => \$verbose,
);
if ($help) {
    print "Usage: fuzzy-cleanmysql [Options]\n";
    print "\n";
    print "Available options:\n";
    print "--age=i      Global age in hours to keep in db\n";
    print "--config=s   Specify location of FuzzyOcr.cf\n";
    print "             Default: /etc/spamassassin/FuzzyOcr.cf\n";
    print "--hash=i     Number of hours old to keep in Hash db\n";
    print "--safe=i     Number of hours old to keep in Safe db\n";
    print "--verbose    Show more informations\n";
    print "\n";
    exit 1;
}
# Convert hours to seconds
$age{'age'} *= 60 * 60;
$age{'hash'} *= 60 * 60;
$age{'safe'} *= 60 * 60;
$age{'safe'} = $age{'safe'} ? $age{'safe'} : $age{'age'};
# Read custom paths from FuzzyOcr.cf
my $app_path = q(/usr/local/netpbm/bin:/usr/local/bin:/usr/bin);
open CONFIG, "< $cfgfile" or warn "Can't read configuration file, using defaults...\n";
while () {
    chomp;
    if ($_ =~ m/^focr_bin_(\w+) (.+)/) {
        $App{$1} = $2;
        printf "Found custom path \"$2\" for application \"$1\"\n" if $verbose;
    }
    if ($_ =~ m/^focr_path_bin (.+)/) {
        $app_path = $1;
        printf "Found new path: \"$1\"\n" if $verbose;
    }
    if ($_ =~ m/^focr_enable_image_hashing (\d)/) {
        $App{hashing_type} = $1;
        printf "Found DB Hashing\n" if ($verbose and $1 == 2);
        printf "Found MySQL Hashing\n" if ($verbose and $1 == 3);
    }
    if ($_ =~ m/^focr_mysql_(\w+) (.+)/) {
        $MySQL{$1} = $2;
        printf "Found MySQL option $1 => '$2'\n" if $verbose;
    }
    if ($_ =~ m/^focr_threshold_max_hash (.+)/) {
        $App{max_hash} = $1;
        printf "Updated Thresold{max_hash} = $1\n" if $verbose;
    }
}
close CONFIG;
# make shure we have this threshold set
$App{max_hash} = 5 unless defined $App{max_hash};
# search path for bin_util unless already specified in configuration file
foreach my $app (@bin_utils) {
    next if defined $App{$app};
    foreach my $d (split(':',$app_path)) {
        if (-x "$d/$app") {
            $App{$app} = "$d/$app";
            last;
        }
    }
}
sub get_ddb {
    my %dopts = ( AutoCommit => 1 );
    my $dsn = "DBI:mysql:database=$database";
    if (defined $socket) {
        $dsn .= ";mysql_socket=$socket";
    } else {
        $dsn .= ";host=$hostname";
        $dns .= ";port=$port" unless $port == 3306;
    }
    printf "Connecting to: $dsn\n" if $verbose;
    return DBI->connect($dsn, $username, $password,\%dopts) or die("Could not connect!");
}
if ($App{hashing_type} == 3) {
 my $ddb = get_ddb();
  if ($ddb) {
    my $sql;
    foreach my $ff (sort keys %Files) {
      $ff =~ s/db_//;
      $sqlbase = "FROM $MySQL{$ff} WHERE $MySQL{$ff}.\`check\` < ?";
      my $timestamp = time;
      $timestamp = $timestamp - $age{$ff};
      $sql = "DELETE $sqlbase";
      if ( $verbose ) {
        printf "Delete from Table $MySQL{$ff}\n";
        print "$sql,  $timestamp\n";
        print "Timestamp is ", scalar(localtime($timestamp)), "\n";
        print "That's $age{$ff} seconds earlier than now.\n";
        print "\n";
      }
      $ddb->do($sql,undef,$timestamp);
    }
    $ddb->disconnect;
  }
}
EOF

chmod +x /usr/sbin/fuzzy-cleanmysql

# Edit MySQL script

# Import Script

echo ""
echo "Finished Downloading and Configuring FuzzyOCR."
sleep 2
# **END** Download and Configure FuzzOCR

echo ""
echo "FuzzyOCR Package Installed."
sleep 8
}


# Filtering PDF, XLS and Phishing Spam with ClamAV (Sanesecurity Signatures)
function install_clamavsane () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	C L A M A V   S A N E S E C U R I T Y   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

apt-get install curl rsync -y

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Download and Configure ClamAV Sanesecurity
echo "We are Downloading and Configuring ClamAV Sanesecurity"
echo ""

mkdir /usr/src/sanesecurity && cd /usr/src/sanesecurity
wget http://downloads.sourceforge.net/project/unofficial-sigs/clamav-unofficial-sigs-3.7.2.tar.gz
tar -zxf clamav-unofficial-sigs-3.7.2.tar.gz && cd clamav-unofficial-sigs-3.7.2
mv clamav-unofficial-sigs.sh /usr/sbin
mv clamav-unofficial-sigs.conf /etc/
chmod +x /usr/sbin/clamav-unofficial-sigs.sh

sed -i '/^clam_dbs=/ c\clam_dbs="/var/lib/clamav"' /etc/clamav-unofficial-sigs.conf
sed -i '/^clamd_pid=/ c\clamd_pid="/var/run/clamav/clamd.pid"' /etc/clamav-unofficial-sigs.conf
sed -i '/^reload_dbs=/ c\reload_dbs="yes"' /etc/clamav-unofficial-sigs.conf
sed -i '/^reload_opt=/ c\reload_opt="kill -USR2 `cat $clamd_pid`" #Signals PID to reload dbs' /etc/clamav-unofficial-sigs.conf
sed -i '/^work_dir=/ c\work_dir="/var/lib/clamav"' /etc/clamav-unofficial-sigs.conf
sed -i '/^user_configuration_complete=/ c\user_configuration_complete="yes"' /etc/clamav-unofficial-sigs.conf

echo ""
echo "Finished Downloading and Configuring ClamAV Sanesecurity."
sleep 2
# **END** Download and Configure ClamAV Sanesecurity

echo ""
echo "ClamAV Sanesecurity Package Installed."
sleep 8
}


# Greylist Package Install
function install_greyfix () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	G R E Y L I S T   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

cd /usr/src
wget http://www.kim-minh.com/pub/greyfix/greyfix-0.4.0.tar.gz
tar -xf greyfix-0.4.0.tar.gz && cd greyfix-0.4.0
./configure --localstatedir=/var
make
make install

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Configuring Postfix
echo "We are Configuring Postfix"
echo ""


cat >> /etc/postfix/master.cf <<EOF

greyfix    unix  -        n       n       -        -       spawn
   user=nobody  argv=/usr/local/sbin/greyfix   --greylist-delay 60  -/ 24
EOF

/etc/init.d/postfix restart

echo ""
echo "Finished Configuring Postfix."
sleep 2
# **END** Configure Postfix

echo ""
echo "Greylist Package Installed."
sleep 8
}


# KAM Package Install
function install_kam () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	K A M   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

cat > /etc/cron.daily/kam.sh <<EOF
#!/bin/bash
  
 # Original version modified by Andrew MacLachlan (andrew@gdcon.net)
 # Added additional MailScanner restarts on inital restart failure
 # Made script run silently for normal (successful) operation
 # Increased UPDATEMAXDELAY to 900 from 600
 
 # Insert a random delay up to this value, to spread virus updates round
 # the clock. 1800 seconds = 30 minutes.
 # Set this to 0 to disable it.
 UPDATEMAXDELAY=0
 if [ -f /opt/MailScanner/var/MailScanner ] ; then
 . /opt/MailScanner/var/MailScanner
 fi
 export UPDATEMAXDELAY
 
 if [ "x$UPDATEMAXDELAY" = "x0" ]; then
 :
 else
 logger -p mail.info -t KAM.cf.sh Delaying cron job up to $UPDATEMAXDELAY seconds
 perl -e "sleep int(rand($UPDATEMAXDELAY));"
 fi
 
 # JKF Fetch KAM.cf
 #echo Fetching KAM.cf...
 cd /etc/mail/spamassassin
 rm -f KAM.cf
 wget -O KAM.cf http://www.peregrinehw.com/downloads/SpamAssassin/contrib/KAM.cf > /dev/null 2>&1
 if [ "$?" = "0" ]; then
 #echo It completed and fetched something
 if ( tail -10 KAM.cf | grep -q '^#.*EOF' ); then
 # echo It succeeded so make a backup
 cp -f KAM.cf KAM.cf.backup
 else
 echo ERROR: Could not find EOF marker
 cp -f KAM.cf.backup KAM.cf
 fi
 else
 echo It failed to complete properly
 cp -f KAM.cf.backup KAM.cf
 fi
 #echo Reloading MailScanner and SpamAssassin configuration rules
 /etc/init.d/mailscanner reload > /dev/null 2>&1
 if [ $? != 0 ] ; then
 echo "MailScanner reload failed - Retrying..."
 /etc/init.d/mailscanner force-reload
 if [ $? = 0 ] ; then
 echo "MailScanner reload succeeded."
 else
 echo "Stopping MailScanner..."
 /etc/init.d/mailscanner stop
 echo "Waiting for a minute..."
 perl -e "sleep 60;"
 echo "Attemping to start MailScanner..."
 /etc/init.d/mailscanner start
 fi
 
 fi
EOF

chmod +x /etc/cron.daily/kam.sh

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

echo ""
echo "KAM Package Installed."
sleep 8
}


# Scamnailer Package Install
function install_scamnailer () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	S C A M N A I L E R   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

cat > /opt/MailScanner/bin/update_scamnailer <<EOF
#!/usr/bin/perl
 
#
# (c) 2009 Julian Field ‹ScamNailer@ecs.soton.ac.uk›
#          Version 2.05
#
# This file is the copyright of Julian Field ‹ScamNailer@ecs.soton.ac.uk›,
# and is made freely available to the entire world. If you intend to
# make any money from my work, please contact me for permission first!
# If you just want to use this script to help protect your own site's
# users, then you can use it and change it freely, but please keep my
# name and email address at the top.
#
 
use strict;
use File::Temp;
use Net::DNS::Resolver;
use LWP::UserAgent;
use FileHandle;
use DirHandle;
 
# Filename of list of extra addresses you have added, 1 per line.
# Does not matter if this file does not exist.
my $local_extras = '/etc/MailScanner/ScamNailer.local.addresses';
 
# Output filename, goes into SpamAssassin. Can be over-ridden by just
# adding the output filename on the command-line when you run this script.
my $output_filename = '/etc/mail/spamassassin/ScamNailer.cf';
 
# This is the location of the cache used by the DNS-based updates to the
# phishing database.
my $emailscurrent = '/var/cache/ScamNailer/';
 
# Set this next value to '' if ou are not using MailScanner.
# Or else change it to any command you need to run after updating the
# SpamAssassin rules, such as '/sbin/service spamd restart'.
my $mailscanner_restart = '/etc/init.d/mailscanner force-reload';
 
# The SpamAssassin score to assign to the final rule that fires if any of
# the addresses hit. Multiple hits don't increase the score.
#
# I use a score of 0.1 with this in MailScanner.conf:
# SpamAssassin Rule Actions = SCAMNAILER=>not-deliver,store,forward postmaster@my-domain.com, header "X-Anti-Phish: Was to _TO_"
# If you don't understand that, read the section of MailScanner.conf about the
# "SpamAssassin Rule Actions" setting.
my $SA_score = 4.0;
 
# How complicated to make each rule. 20 works just fine, leave it alone.
my $addresses_per_rule = 20;
 
my $quiet = 1 if grep /quiet|silent/, @ARGV;
if (grep /help/, @ARGV) {
  print STDERR "Usage: $0 [ --quiet ]\n";
  exit(1);
}
 
my($count, $rule_num, @quoted, @addresses, @metarules);
#local(*YPCAT, *SACF);
local(*SACF);
 
$output_filename = $ARGV[0] if $ARGV[0]; # Use filename if they gave one
# First do all the addresses we read from DNS and anycast and only do the
# rest if needed.
if (GetPhishingUpdate()) {
open(SACF, ">$output_filename") or die "Cannot write to $output_filename $!";
 
print SACF "# ScamNailer rules\n";
print SACF "# Generated by $0 at " . `date` . "\n";
 
# Now read all the addresses we generated from GetPhishingUpdate().
open(PHISHIN, $emailscurrent . 'phishing.emails.list')
  or die "Cannot read " . $emailscurrent . "phishing.emails.list, $!\n";
while(
<phishin>) {
  chomp;
  s/^\s+//g;
  s/\s+$//g;
  s/^#.*$//g;
  next if /^\s*$/;
  next unless /^[^@]+\@[^@]+$/;
 
  push @addresses, $_; # This is for the report
  s/[^0-9a-z_-]/\\$&/ig; # Quote every non-alnum
  s/\\\*/[0-9a-z_.+-]*/g; # Unquote any '*' characters as they map to .*
  # Find all the numbers just before the @ and replace with them digit wildcards
  s/([0-9a-z_.+-])\d{1,3}\\\@/$1\\d+\\@/i;
  #push @quoted, '(' . $_ . ')';
  push @quoted, $_;
  $count++;
 
  if ($count % $addresses_per_rule == 0) {
    # Put them in 10 addresses at a time
    $rule_num++;
    # Put a start-of-line/non-address character at the front,
    # and an end-of-line /non-address character at the end.
    print SACF "header __SCAMNAILER_H$rule_num ALL =~ /" .
               '(^|[;:\s])(?:' . join('|',@quoted) . ')($|[^0-9a-z_.+-])' .
               "/i\n";
    push @metarules, "__SCAMNAILER_H$rule_num";
    print SACF "uri __SCAMNAILER_B$rule_num /" .
               '^mailto:(?:' . join('|',@quoted) . ')$' .
               "/i\n";
    push @metarules, "__SCAMNAILER_B$rule_num";
    undef @quoted;
    undef @addresses;
  }
}
close PHISHIN;
 
# Put in all the leftovers, if any
if (@quoted) {
  $rule_num++;
    print SACF "header __SCAMNAILER_H$rule_num ALL =~ /" .
               '(^|[;:\s])(?:' . join('|',@quoted) . ')($|[^0-9a-z_.+-])' .
               "/i\n";
    push @metarules, "__SCAMNAILER_H$rule_num";
    print SACF "uri __SCAMNAILER_B$rule_num /" .
               '^mailto:(?:' . join('|',@quoted) . ')$' .
               "/i\n";
    push @metarules, "__SCAMNAILER_B$rule_num";
}
 
print SACF "\n# ScamNailer combination rule\n\n";
print SACF "meta     SCAMNAILER " . join(' || ',@metarules) . "\n";
print SACF "describe SCAMNAILER Mentions a spear-phishing address\n";
print SACF "score    SCAMNAILER $SA_score\n\n";
print SACF "# ScamNailer rules ($count) END\n";
 
close SACF;
 
# And finally restart MailScanner to use the new rules
$mailscanner_restart .= " >/dev/null 2>&1" if $quiet;
system($mailscanner_restart) if $mailscanner_restart;
 
exit 0;
}
 
sub GetPhishingUpdate {
  my $cache = $emailscurrent . 'cache/';
  my $status = $emailscurrent . 'status';
  my $urlbase = "http://www.mailscanner.tv/emails.";
  my $target= $emailscurrent . 'phishing.emails.list';
  my $query="emails.msupdate.greylist.bastionmail.com";
 
  my $baseupdated = 0;
  if (! -d $emailscurrent) {
    print "Working directory is not present - making....." unless $quiet;
    mkdir ($emailscurrent) or die "failed";
    print " ok!\n" unless $quiet;
  }
  if (! -d $cache) {
    print "Cache directory is not present - making....." unless $quiet;
    mkdir ($cache) or die "failed";
    print " ok!\n" unless $quiet;
  }
  if (! -s $target) {
    open (FILE,">$target") or die
      "Failed to open target file so creating a blank file";
    print FILE "# Wibble";
    close FILE;
  } else {
    # So that clean quarantine doesn't delete it!
    utime(time(), time(), $emailscurrent);
  }
 
  my ($status_base, $status_update);
 
  $status_base=-1;
  $status_update=-1;
 
  if (! -s $status) {
    print "This is the first run of this program.....\n" unless $quiet;
  } else {
    print "Reading status from $status\n" unless $quiet;
    open(STATUS_FILE, $status) or die "Unable to open status file\n";
    my $line=<status_file>;
    close (STATUS_FILE);
 
    # The status file is text.text
    if ($line =~ /^(.+)\.(.+)$/) {
      $status_base=$1;
      $status_update=$2;
    }
  }
 
  print "Checking that $cache$status_base exists..." unless $quiet;
  if ((! -s "$cache$status_base") && (!($status_base eq "-1"))) {
    print " no - resetting....." unless $quiet;
    $status_base=-1;
  }
  print " ok\n" unless $quiet;
 
  print "Checking that $cache$status_base.$status_update exists..." unless $quiet;
  if ((! -s "$cache$status_base.$status_update") && ($status_update>0)) {
    print " no - resetting....." unless $quiet;
    $status_update=-1;
  }
  print " ok\n" unless $quiet;
 
  my $currentbase = -1;
  my $currentupdate = -1;
 
  # Lets get the current version
  my $res = Net::DNS::Resolver->new();
  my $RR = $res->query($query, 'TXT');
  my @result;
  if ($RR) {
    foreach my $rr ($RR->answer) {
      my $text = $rr->rdatastr;
      if ($text =~ /^"emails\.(.+)\.(.+)"$/) {
        $currentbase=$1;
        $currentupdate=$2;
        last;
      }
    }
  }
 
  die "Failed to retrieve valid current details\n" if $currentbase eq "-1";
 
  print "I am working with: Current: $currentbase - $currentupdate and Status: $status_base - $status_update\n" unless $quiet;
 
  my $generate=0;
 
  # Create a user agent object
  my $ua = LWP::UserAgent->new;
  $ua->agent("UpdateBadPhishingSites/0.1 ");
  # Patch from Heinz.Knutzen@dataport.de
  $ua->env_proxy;
 
  if (!($currentbase eq $status_base)) {
    print "This is base update\n" unless $quiet;
    $status_update = -1;
    $baseupdated = 1;
    # Create a request
    #print "Getting $urlbase . $currentbase\n" unless $quiet;
    my $req = HTTP::Request->new(GET => $urlbase.$currentbase);
    # Pass request to the user agent and get a response back
    my $res = $ua->request($req);
    # Check the outcome of the response
    if ($res->is_success) {
      open (FILE, ">$cache/$currentbase") or die "Unable to write base file ($cache/$currentbase)\n";
      print FILE $res->content;
      close (FILE);
    } else {
      warn "Unable to retrieve $urlbase.$currentbase :".$res->status_line, "\n";
    }
    $generate=1;
  } else {
    print "No base update required\n" unless $quiet;
  }
 
  # Now see if the sub version is different
  if (!($status_update eq $currentupdate)) {
    my %updates=();
 
    print "Update required\n" unless $quiet;
    if ($currentupdate‹$status_update) {
      # In the unlikely event we roll back a patch - we have to go from the base
      print "Error!: $currentupdate<$status_update\n" unless $quiet;
      $generate = 1;
      $status_update = 0;
    }
    # If there are updates avaliable and we haven't donloaded them
    # yet we need to reset the counter
    if ($currentupdate>0) {
      if ($status_update<1) {
        $status_update=0;
      }
      my $i;
      # Loop through each of the updates, retrieve it and then add
      # the information into the update array
      for ($i=$status_update+1; $i<=$currentupdate; $i++) {
        print "Retrieving $urlbase$currentbase.$i\n" unless $quiet;
        #print "Getting $urlbase . $currentbase.$i\n" unless $quiet;
        my $req = HTTP::Request->new(GET => $urlbase.$currentbase.".".$i);
        my $res = $ua->request($req);
        warn "Failed to retrieve $urlbase$currentbase.$i"
          unless $res->is_success;
        my $line;
        foreach $line (split("\n", $res->content)) {
          # Is it an addition?
          if ($line =~ /^\> (.+)$/) {
            if (defined $updates{$1}) {
              if ($updates{$1} eq "<") {
                delete $updates{$1};
              }
            } else {
              $updates{$1}=">";
            }
          }
          # Is it an removal?
          if ($line =~ /^\< (.+)$/) {
            if (defined $updates{$1}) {
              if ($updates{$1} eq ">") {
                delete $updates{$1};
              }
            } else {
              $updates{$1}="<";
            }
          }
        }
      }
      # OK do we have a previous version to work from?
      if ($status_update>0) {
        # Yes - we open the most recent version
        open (FILE, "$cache$currentbase.$status_update") or die
          "Unable to open base file ($cache/$currentbase.$status_update)\n";
      } else {                        # No - we open the the base file
        open (FILE, "$cache$currentbase") or die
          "Unable to open base file ($cache/$currentbase)\n";
      }
      # Now open the new update file
      print "$cache$currentbase.$currentupdate\n" unless $quiet;
      open (FILEOUT, ">$cache$currentbase.$currentupdate") or die
        "Unable to open new base file ($cache$currentbase.$currentupdate)\n";
 
      # Loop through the base file (or most recent update)
      while (<file>) {
        chop;
        my $line=$_;
 
        if (defined ($updates{$line})) {
          # Does the line need removing?
          if ($updates{$line} eq "<") {
            $generate=1;
            next;
          }
          # Is it marked as an addition but already present?
          elsif ($updates{$line} eq ">") {
            delete $updates{$line};
          }
        }
        print FILEOUT $line."\n";
      }
      close (FILE);
      my $line;
      # Are there any additions left
      foreach $line (keys %updates) {
        if ($updates{$line} eq ">") {
          print FILEOUT $line."\n" ;
          $generate=1;
        }
      }
      close (FILEOUT);
    }
 
  }
 
  # Changes have been made
  if ($generate) {
    print "Updating live file $target\n" unless $quiet;
    my $file="";
    if ($currentupdate>0) {
      $file="$cache/$currentbase.$currentupdate";
    } else {
      $file="$cache/$currentbase";
    }
    if ($file eq "") {
      die "Unable to work out file!\n";
    }
 
    system ("mv -f $target $target.old");
    system ("cp $file $target");
 
    open(STATUS_FILE, ">$status") or die "Unable to open status file\n";
    print STATUS_FILE "$currentbase.$currentupdate\n";
    close (STATUS_FILE);
  }
 
  my $queuedir = new DirHandle;
  my $file;
  my $match1 = "^" . $currentbase . "\$";
  my $match2 = "^" . $currentbase . "." . $currentupdate . "\$";
  $queuedir->open($cache) or die "Unable to do clean up\n";
  while(defined($file = $queuedir->read())) {
    next if $file eq '.' || $file eq '..';
    next if $file =~ /$match1/;
    next if $file =~ /$match2/;
    print "Deleting cached file: $file.... " unless $quiet;
    unlink($cache.$file) or die "failed";
    print "ok\n" unless $quiet;
  }
  $queuedir->close();
  $generate;
}

EOF

chmod +x /opt/MailScanner/bin/update_scamnailer

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

echo ""
echo "Scamnailer Package Installed."
sleep 8
}


# Firehol Package Install
function install_firehol () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	F I R E H O L   P A C K A G E   I N S T A L L";
echo "------------------------------------------------------------------------------";

# **START** Install base software
echo "We are installing base software."
echo ""

apt-get install firehol -y
sed -i "/^START_FIREHOL=/ c\START_FIREHOL=YES" /etc/default/firehol

echo ""
echo "Finished installing base software."
sleep 2
# **END** Install base software

# **START** Configuring Update Script
echo "We are Configuring Update Script"
echo ""

##PROBLEM WITH FILE ${tempfile}
cat > /usr/sbin/get-iana <<EOF
#!/bin/bash
 # $Id: get-iana.sh,v 1.13 2010/09/12 13:55:00 jcb Exp $
   #
   # $Log: get-iana.sh,v $
   # Revision 1.13 2010/09/12 13:55:00 jcb
   # Updated for latest IANA reservations format.
   #
   # Revision 1.12 2008/03/17 22:08:43 ktsaou
   # Updated for latest IANA reservations format.
   #
   # Revision 1.11 2007/06/13 14:40:04 ktsaou
   # *** empty log message ***
   #
   # Revision 1.10 2007/05/05 23:38:31 ktsaou
   # Added support for external definitions of:
   #
   # RESERVED_IPS
   # PRIVATE_IPS
   # MULTICAST_IPS
   # UNROUTABLE_IPS
   #
   # in files under the same name in /etc/firehol/.
   # Only RESERVED_IPS is mandatory (firehol will complain if it is not  there,
   # but it will still work without it), and is also the only file that  firehol
   # checks how old is it. If it is 90+ days old, firehol will complain  again.
   #
   # Changed the supplied get-iana.sh script to generate the RESERVED_IPS  file.
   # FireHOL also instructs the user to use this script if the file is  missing
   # or is too old.
   #
   # Revision 1.9 2007/04/29 19:34:11 ktsaou
   # *** empty log message ***
   #
   # Revision 1.8 2005/06/02 15:48:52 ktsaou
   # Allowed 127.0.0.1 to be in RESERVED_IPS
   #
   # Revision 1.7 2005/05/08 23:27:23 ktsaou
   # Updated RESERVED_IPS to current IANA reservations.
   #
   # Revision 1.6 2004/01/10 18:44:39 ktsaou
   # Further optimized and reduced PRIVATE_IPS using:
   # http://www.vergenet.net/linux/aggregate/
   #
   # The supplied get-iana.sh uses .aggregate. if it finds it in the path.
   # (aggregate is the name of this program when installed on Gentoo)
   #
   # Revision 1.5 2003/08/23 23:26:50 ktsaou
   # Bug #793889:
   # Change #!/bin/sh to #!/bin/bash to allow FireHOL run on systems that
   # bash is not linked to /bin/sh.
   #
   # Revision 1.4 2002/10/27 12:44:42 ktsaou
   # CVS test
   #
 #
   # Program that downloads the IPv4 address space allocation by IANA
   # and creates a list with all reserved address spaces.
   #
 IPV4_ADDRESS_SPACE_URL="http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt"
 # The program will match all rows in the file which start with a  number, have a slash,
   # followed by another number, for which the following pattern will also  match on the
   # same rows
   IANA_RESERVED="(RESERVED|UNALLOCATED)"
 # which rows that are matched by the above, to ignore
   # (i.e. not include them in RESERVED_IPS)?
   #IANA_IGNORE="(Multicast|Private use|Loopback|Local  Identification)"
   IANA_IGNORE="Multicast"
 tempfile="/tmp/iana.$$.$RANDOM"
 AGGREGATE="`which aggregate 2>/dev/null`"
   if [ -z "${AGGREGATE}" ]
   then
   AGGREGATE="`which aggregate 2>/dev/null`"
   fi
 if [ -z "${AGGREGATE}" ]
   then
   echo >&2
   echo >&2
   echo >&2 "WARNING"
   echo >&2 "Please install 'aggregate' to shrink the list of  IPs."
   echo >&2
   echo >&2
   fi
 echo >&2
   echo >&2 "Fetching IANA IPv4 Address Space, from:"
   echo >&2 "${IPV4_ADDRESS_SPACE_URL}"
   echo >&2
 wget -O - -proxy=off "${IPV4_ADDRESS_SPACE_URL}" |\
   egrep " *[0-9]+/[0-9]+.*${IANA_RESERVED}" |\
   egrep -vi "${IANA_IGNORE}" |\
   sed -e 's:^ *\([0-9]*/[0-9]*\).*:\1:' |\
   (
 while IFS="/" read range net
   do
   if [ ! $net -eq 8 ]
   then
   echo >&2 "Cannot handle network masks of $net bits  ($range/$net)"
   continue
   fi
 first=`echo $range | cut -d '-' -f 1`
   first=`expr $first + 0`
   last=`echo $range | cut -d '-' -f 2`
   last=`expr $last + 0`
 x=$first
   while [ ! $x -gt $last ]
   do
   # test $x -ne 127 && echo "$x.0.0.0/$net"
   echo "$x.0.0.0/$net"
   x=$[x + 1]
   done
   done
   ) | \
   (
   if [ ! -z "${AGGREGATE}" -a -x "${AGGREGATE}" ]
   then
   "${AGGREGATE}"
   else
   cat
   fi
   ) >"${tempfile}"
 echo >&2
   echo >&2
   echo >&2 "FOUND THE FOLLOWING RESERVED IP RANGES:"
   printf "RESERVED_IPS=\""
   i=0
   for x in `cat ${tempfile}`
   do
   i=$[i + 1]
   printf "${x} "
   done
   printf "\"\n"
 if [ $i -eq 0 ]
   then
   echo >&2
   echo >&2
   echo >&2 "Failed to find reserved IPs."
   echo >&2 "Possibly the file format has been changed, or I  cannot fetch the URL."
   echo >&2
 rm -f ${tempfile}
   exit 1
   fi
   echo >&2
   echo >&2
   echo >&2 "Differences between the fetched list and the list  installed in"
   echo >&2 "/etc/firehol/RESERVED_IPS:"
 echo >&2 "# diff /etc/firehol/RESERVED_IPS  ${tempfile}"
   diff /etc/firehol/RESERVED_IPS ${tempfile}
 if [ $? -eq 0 ]
   then
   echo >&2
   echo >&2 "No  differences found."
   echo >&2
 rm -f ${tempfile}
   exit 0
   fi
 echo >&2
   echo >&2
   echo >&2 "Would you like to save this list to  /etc/firehol/RESERVED_IPS"
   echo >&2 "so that FireHOL will automatically use it from  now on?"
   echo >&2
   while [ 1 = 1 ]
   do
   printf >&2 "yes or no > "
   read x
 case "${x}" in
   yes) cp -f /etc/firehol/RESERVED_IPS /etc/firehol/RESERVED_IPS.old  2>/dev/null
   cat "${tempfile}" >/etc/firehol/RESERVED_IPS || exit 1
   echo >&2 "New RESERVED_IPS written to  '/etc/firehol/RESERVED_IPS'."
   echo "Firehol will now be restart"
   sleep 3
   /etc/init.d/firehol restart
   break
   ;;
 no)
   echo >&2 "Saved nothing."
   break
   ;;
 *) echo >&2 "Cannot understand '${x}'."
   ;;
   esac
   done
 rm -f ${tempfile}
EOF

cat > /usr/sbin/update-iana <<EOF
#!/bin/sh
 /usr/sbin/get-iana  < /etc/firehol/get-iana-answerfile
EOF

cat > /etc/firehol/get-iana-answerfile <<EOF
yes
EOF

chmod +x /usr/sbin/get-iana
chmod +x /usr/sbin/update-iana

echo ""
echo "Finished Configuring Update Script."
sleep 2
# **END** Configuring Update Script

# **START** Configuring Firehol
echo "We are Configuring Firehol"
echo ""

sed -i "/^interface/ c\interface any internet" /etc/firehol/firehol.conf
sed -i "/^interface/ c\interface any internet" /etc/firehol/firehol.conf
sed -i "/client all/ c\   protection strong" /etc/firehol/firehol.conf
cat >> /etc/firehol/firehol.conf <<EOF
   server "icmp ping ICMP ssh http https telnet webmin dns dcc echo smtp" accept
   client all accept
EOF

echo ""
echo "Finished Configuring Firehol."
sleep 2
# **END** Configuring Firehol

echo ""
echo "Firehol Package Installed."
sleep 8
}


# Branding
function install_branding () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	B R A N D I N G   I N S T A L L";
echo "------------------------------------------------------------------------------";

echo "We are about to Brand SpamSnake."
echo ""

#commands

echo ""
echo "Branded Successfully."
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

install_baruwaweb
install_SPF
install_fuzzyocr

sleep 8
}

# Phase 5
function phase_5 () {
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	P H A S E   5";
echo "------------------------------------------------------------------------------";

install_clamavsane
install_greyfix
install_kam
install_scamnailer
install_firehol
install_branding

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
	echo "f) Phase 5 Setup"
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
	echo "k) Install Baruwa Webserver"
	echo "l) Install SPF for Postfix"
	echo "m) Install FuzzyOCR"
	echo "n) Install Greyfix"
	echo "o) Install Scamnailer"
	echo "p) Install Firehol"
	echo "q) Install Branding"
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
		k) install_baruwaweb ;;
		l) install_SPF ;;
		m) install_fuzzyocr ;;
		n) install_greyfix ;;
		o) install_scamnailer ;;
		p) install_firehol ;;
		q) install_branding ;;
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