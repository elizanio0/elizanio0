#!/bin/bash 

#Variables
IP=$(hostname -I | awk '{print $2}')
PasswordGenerator=$(</dev/urandom tr -dc '[:alnum:]' | head -c15; echo "")
PSK=$(openssl rand -base64 24)
export DEBIAN_FRONTEND=noninteractive

#Set proper mirrors
mv /etc/apt/sources.list /etc/apt/sources.list_backup
tee /etc/apt/sources.list <<EOF
deb https://mirrors.neterra.net/ubuntu/ focal main restricted universe
deb https://mirrors.neterra.net/ubuntu/ focal-updates main restricted universe
deb https://mirrors.neterra.net/ubuntu/ focal-security main restricted universe multiverse
deb http://archive.canonical.com/ubuntu focal partner
EOF

#Install Software and upgrade the server
apt-get -yq --allow-releaseinfo-change update
apt-get install -y ppp xl2tpd strongswan libcharon-extra-plugins strongswan-pki iptables-persistent curl

#Configure StrongSwan
tee -a /etc/ipsec.secrets <<EOF
$IP %any : PSK $PSK
EOF

tee /etc/ipsec.conf <<EOF
config setup
		logip=no
		audit-log=no
conn vpnserver
        type=transport
        authby=secret
        rekey=no
        keyingtries=1
        left=%any
        leftprotoport=udp/l2tp
        leftid=$IP
        right=%any
        rightprotoport=udp/%any
        auto=add
EOF
chmod 664 /etc/ipsec.secrets

tee /etc/strongswan.d/charon-logging.conf <<EOF
charon {
    syslog {
        daemon {
            default = -1
       }
   }
}

charon-systemd : charon {
    journal {
        default = -1
   }
}
EOF

#Disable logs
tee /etc/rsyslog.d/00-vpn.conf <<EOF
#  /etc/rsyslog.conf	Configuration file for rsyslog.
#
#			For more information see
#			/usr/share/doc/rsyslog-doc/html/rsyslog_conf.html


#################
#### MODULES ####
#################

$ModLoad imuxsock # provides support for local system logging
$ModLoad imklog   # provides kernel logging support
#$ModLoad immark  # provides --MARK-- message capability

# provides UDP syslog reception
#$ModLoad imudp
#$UDPServerRun 514

# provides TCP syslog reception
#$ModLoad imtcp
#$InputTCPServerRun 514


###########################
#### GLOBAL DIRECTIVES ####
###########################

#
# Use traditional timestamp format.
# To enable high precision timestamps, comment out the following line.
#
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

#
# Set the default permissions for all log files.
#
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Include all config files in /etc/rsyslog.d/
#
$IncludeConfig /etc/rsyslog.d/*.conf


###############
#### RULES ####
###############

#
# Filter out all L2TP/IPsec entries to prevent IP address logging
#
if $programname == 'pppd' then ~
if $programname == 'charon' then ~
if $programname == 'xl2tpd' then ~
:msg, contains, "ppp" ~

#
# First some standard log files.  Log by facility.
#
auth,authpriv.*			/var/log/auth.log
*.*;auth,authpriv.none		-/var/log/syslog
#cron.*				/var/log/cron.log
#daemon.*                       -/var/log/daemon.log
kern.*				-/var/log/kern.log
lpr.*				-/var/log/lpr.log
mail.*				-/var/log/mail.log
user.*				-/var/log/user.log

#
# Logging for the mail system.  Split it up so that
# it is easy to write scripts to parse these files.
#
mail.info			-/var/log/mail.info
mail.warn			-/var/log/mail.warn
mail.err			/var/log/mail.err

#
# Logging for INN news system.
#
news.crit			/var/log/news/news.crit
news.err			/var/log/news/news.err
news.notice			-/var/log/news/news.notice

#
# Some "catch-all" log files.
#
*.=debug;\
	auth,authpriv.none;\
	news.none;mail.none	-/var/log/debug
*.=info;*.=notice;*.=warn;\
	auth,authpriv.none;\
	cron,daemon.none;\
	mail,news.none		-/var/log/messages

#
# Emergencies are sent to everybody logged in.
#
*.emerg				:omusrmsg:*

#
# I like to have messages displayed on the console, but only on a virtual
# console I usually leave idle.
#
#daemon,mail.*;\
#	news.=crit;news.=err;news.=notice;\
#	*.=debug;*.=info;\
#	*.=notice;*.=warn	/dev/tty8

# The named pipe /dev/xconsole is for the `xconsole' utility.  To use it,
# you must invoke `xconsole' with the `-file' option:
# 
#    $ xconsole -file /dev/xconsole [...]
#
# NOTE: adjust the list below, or you'll go crazy if you have a reasonably
#      busy site..
#
daemon.*;mail.*;\
	news.err;\
	*.=debug;*.=info;\
	*.=notice;*.=warn	|/dev/xconsole
EOF
 
systemctl restart rsyslog 

#Configure L2TP
iptables -t nat -A POSTROUTING -j SNAT --to-source $IP -o venet0
iptables -t nat -A POSTROUTING -o venet0 -j MASQUERADE

#Save rules
systemctl enable netfilter-persistent.service
iptables-save > /etc/iptables/rules.v4

#Configurations
tee /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701
access control = no
 
[lns default]
ip range = 10.0.3.2-10.0.3.254
local ip = 10.0.3.1
require authentication = yes
name = dedicatedvpn
pppoptfile = /etc/ppp/options.xl2tpd
EOF

tee /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 9.9.9.9
ms-dns 149.112.112.112
mtu 1420
EOF

#Configure PPP
tee /etc/ppp/chap-secrets <<EOF
dedicatedvpn          *       $PasswordGenerator           *
EOF

#Apply configuration
systemctl enable strongswan-starter.service
systemctl enable xl2tpd.service
systemctl restart xl2tpd.service
systemctl restart strongswan-starter.service

#Configure SSH.
sed -i "s/#Port 22/Port 22000/g" /etc/ssh/sshd_config
systemctl restart sshd

#Remove bloatware
apt-get remove exim* apache2* python* pwgen tcpdump telnet -y

#Update the system
printf '\n' | apt-get -yq --allow-releaseinfo-change upgrade
apt-get clean
