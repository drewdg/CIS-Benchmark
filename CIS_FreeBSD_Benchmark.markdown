# 2 Services

## 2.1 inetd Services

inetd is a super-server daemon that provides internet services and passes connections to
configured services. While not commonly used inetd and any unneeded inetd based
services should be disabled if possible.

## 2.1.1 Ensure xinetd is not installed

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The eXtended InterNET Daemon ( <code>xinetd</code> ) is an open source super daemon that replaced
the original <code>inetd</code> daemon. The <code>xinetd</code> daemon listens for well known services and
dispatches the appropriate daemon to properly respond to service requests.

#### Rationale:
If there are no <code>xinetd</code> services required, it is recommended that the package be removed.

#### Audit:
Run the following command to verify <code>xinetd</code> is not installed:
<pre><code># pkg info xinetd
pkg: No package(s) matching xinetd</code></pre>

#### Remediation:
Run the following command to remove xinetd:
<pre><code># pkg delete xinetd</code></pre>

#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.


## 2.2 Special Purpose Services

This section describes services that are installed on systems that specifically need to run
these services. If any of these services are not required, it is recommended that they be
disabled or deleted from the system to reduce the potential attack surface.


## 2.2.1 Time Synchronization

It is recommended that physical systems and virtual guests lacking direct access to the
physical host's clock be configured to synchronize their time using NTP


## 2.2.1.1 Ensure NTP time synchronization is in use

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
System time should be synchronized between all systems in an environment. This is
typically done by establishing an authoritative time server or set of servers and having all
systems synchronize their clocks to them.

#### Rationale:
Time synchronization is important to support time sensitive security mechanisms like
Kerberos and also ensures log files have consistent time records across the enterprise,
which aids in forensic investigations.

#### Audit:
On physical systems or virtual systems where host based time synchronization is not
available verify that NTP is configured and enabled.

Run the following command to verify that NTP is in use:

<pre><code># grep ntpd_enable /etc/rc.conf
ntpd_enable="YES"</code></pre>

#### Remediation:

Add the following line to <code>/etc/rc.conf</code> 

<pre><code>ntpd_enable="YES"</code></pre>

NTP can be started immediately with

<pre><code># service ntpd start</code></pre>

#### CIS Controls:
Version 7

6.1 Utilize Three Synchronized Time Sources
Use at least three synchronized time sources from which all servers and network devices
retrieve time information on a regular basis so that timestamps in logs are consistent.

## 2.2.2 Configure SMTP Authentication

## 2.2.2.1 Ensure SASL is installed

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
SASL is the Simple Authentication and Security Layer, a method for adding authentication support to connection-based protocols. To use SASL, a protocol includes a command for identifying and authenticating a user to a server and for optionally negotiating protection of subsequent protocol interactions.

##### Rationale:
If SASL is used, a security layer is inserted between the protocol and the connection.

##### Audit:
Run the following command and ensure the packages are installed:
<pre><code># pkg info cyrus-sasl
pkg info cyrus-sasl-saslauthd</code></pre>


#### Remediation:
Run the following commands to install cyrus-sasl and saslauth
<pre><code># pkg install cyrus-sasl
# pkg install cyrus-sasl-saslauthd</code></pre>

Next edit or create <code>/usr/local/lib/sasl2/Sendmail.conf</code> and add the following line:
<pre><code>pwcheck_method: saslauthd</code></pre>

Add the following line to <code>/etc/rc.conf</code>:
<pre><code>saslauthd_enable="YES"</code></pre>

Finally, run the following command to start the saslauthd daemon:
<pre><code># service saslauthd start</code></pre>


#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

## 2.2.2.2 Configure SASL for SMTP Authentication

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Configuring SMTP authentication through SASL provides a number of benefits. SMTP authentication adds a layer of security to Sendmail, and provides mobile users who switch hosts the ability to use the same MTA without the need to reconfigure their mail client's settings each time

##### Rationale:
SMTP is responsible for setting up communication between servers. This forces the second server to authorize before mail is sent.

##### Audit:
Run the following commands and verify the outputs:
<pre><code> # grep -E 'SENDMAIL_CFLAGS|SENDMAIL_LDADD' /etc/make.conf
SENDMAIL_CFLAGS=-I/usr/local/include/sasl -DSASL
SENDMAIL_LDADD=/usr/local/lib/libsasl2.so</code></pre>


#### Remediation:
Add the following lines to <code>/etc/make.conf</code>
<pre><code>SENDMAIL_CFLAGS=-I/usr/local/include/sasl -DSASL

SENDMAIL_LDADD=/usr/local/lib/libsasl2.so</code></pre>

Recompile Sendmail by executing the following commands:

<pre><code># cd /usr/src/lib/libsmutil
# make cleandir && make obj && make
# cd /usr/src/lib/libsm
# make cleandir && make obj && make
# cd /usr/src/usr.sbin/sendmail
# make cleandir && make obj && make && make install</code></pre>

Finally, run the following commands:
<pre><code># cd /etc/mail
# make 
# make install restart</code></pre>


#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.


## 2.2.3 Ensure NFS is not enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The Network File System (NFS) is one of the first and most widely distributed file systems
in the UNIX environment. It provides the ability for systems to mount file systems of other
servers through the network.

##### Rationale:
If the system does not export NFS shares, it is recommended that the NFS be disabled to
reduce the remote attack surface.

##### Audit:
Run the following command and verify there is no output:
<pre><code># grep nfs_client_enable /etc/rc.conf</code></pre>


#### Remediation:
Remove the following line from <code>/etc/rc.conf</code> to disable <code>nfs</code>:
<pre><code>nfs_client_enable="YES"</code></pre>

#### Notes:
Additional methods of disabling a service exist. Consult your distribution documentation
for appropriate methods.

#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

## 2.2.4 Ensure RPC is not enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The rpcbind service maps Remote Procedure Call (<code>RPC</code>) services to the ports on which they
listen. <code>RPC</code> processes notify rpcbind when they start, registering the ports they are
listening on and the <code>RPC</code> program numbers they expect to serve. The client system then
contacts rpcbind on the server with a particular <code>RPC</code> program number. The rpcbind service
redirects the client to the proper port number so it can communicate with the requested
service.

#### Rationale:
If the system does not require <code>rpc</code> based services, it is recommended that rpcbind be
disabled to reduce the remote attack surface.

#### Audit:
Run the following command and verify there is no output:
<pre><code># grep rpcbind_enable /etc/rc.conf</code></pre>

#### Remediation:
Remove the following line from <code>/etc/rc.conf</code> to disable <code>rcbind</code>:
<pre><code>nfs_client_enable="YES"</code></pre>

#### Impact:
Because <code>RPC</code>-based services rely on <code>rpcbind</code> to make all connections with incoming client
requests, <code>rpcbind</code> must be available before any of these services start

#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

## 2.2.5 Ensure NIS Server is not enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server
directory service protocol for distributing system configuration files. The NIS server is a
collection of programs that allow for the distribution of configuration files.

#### Rationale:
The NIS service is inherently an insecure system that has been vulnerable to DOS attacks,
buffer overflows and has poor authentication for querying NIS maps. NIS generally has
been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is
recommended that the service be disabled and other, more secure services be used

#### Audit:
Run the following command and verify there is no output:
<pre><code># grep nis_client_enable /etc/rc.conf</code></pre>

#### Remediation:
Remove the following line from <code>/etc/rc.conf</code> to disable <code>NIS</code>:
<pre><code>nis_client_enable="YES"</code></pre>


#### Notes:
Additional methods of disabling a service exist. Consult your distribution documentation
for appropriate methods.

#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

# 3 Network Configuration

This section provides guidance on for securing the network configuration of the system
through kernel parameters, access list control, and firewall settings.

# 3.1 Network Parameters
The following network parameters are intended for use if the system is to act as a host
only. A system is considered host only if the system has a single interface, or has multiple
interfaces but will not be configured as a router.

## 3.1.1 Ensure IP forwarding is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>gateway_enable</code> flag is used to tell the
system whether it can forward packets or not.

#### Rationale:
Setting the flags to <code>NO</code> ensures that a system with multiple interfaces (for example, a hard
proxy), will never be able to forward packets, and therefore, never serve as a router.

#### Audit:
Run the following command and verify there is either no output, or the output matches:
<pre><code># grep gateway_enable /etc/rc.conf
gateway_enable="NO"</code></pre>

#### Remediation:
Edit <code>/etc/rc.conf</code> and add or ammend the line:
<pre><code>gateway_enable="NO"</code></pre>

#### CIS Controls:

Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software


## 3.1.2 Ensure packet redirect sending is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
ICMP Redirects are used to send routing information to other hosts. As a host itself does
not act as a router (in a host only configuration), there is no need to send redirects.

#### Rationale:
An attacker could use a compromised host to send invalid ICMP redirects to other router
devices in an attempt to corrupt routing and have users access a system set up by the
attacker as opposed to a valid system.

#### Audit:
Run the following commands and verify output matches:
<pre><code># sysctl net.inet.ip.redirect
net.inet.ip.redirect: 0</code></pre>
<pre><code># grep "net\.inet\.ip\.redirect" /etc/sysctl.conf
net.ipv4.conf.all.send_redirects=0</code></pre>


#### Remediation:

Set the following parameters in <code>/etc/sysctl.conf</code>:
<pre><code>net.inet.ip.redirect=0</code></pre>

Run the following commands to set the active kernel parameters:

<pre><code># sysctl -w net.inet.ip.redirect=0</code></pre>

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.


# 3.2 Network Parameters

The following network parameters are intended for use on both host only and router
systems. A system acts as a router if it has at least two interfaces and is configured to
perform routing functions.

## 3.2.1 Ensure source routed packets are not accepted

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
In networking, source routing allows a sender to partially or fully specify the route packets
take through a network. In contrast, non-source routed packets travel a path determined
by routers in the network. In some cases, systems may not be routable or reachable from
some locations (e.g. private addresses vs. Internet routable), and so source routed packets
would need to be used.

##### Rationale:
Setting <code>net.inet.ip.accept_sourceroute</code> to 0 disables the system from accepting
source routed packets. Assume this system was capable of routing packets to Internet
routable addresses on one interface and private addresses on another interface. Assume
that the private addresses were not routable to the Internet routable addresses and vice
versa. Under normal routing circumstances, an attacker from the Internet routable
addresses could not use the system as a way to reach the private address systems. If,
however, source routed packets were allowed, they could be used to gain access to the
private address systems as the route could be specified, rather than rely on routing
protocols that did not allow this routing.

#### Audit:
Run the following commands and verify output matches:

<pre><code># sysctl net.inet.ip.accept_sourceroute
net.inet.ip.accept_sourceroute: 0</code></pre>

<pre><code># grep "net\.inet\.ip\.accept_sourceroute" /etc/sysctl.conf
net.inet.ip.accept_sourceroute=0</code></pre>


#### Remediation:
Set the following parameters in <code>/etc/sysctl.conf</code>:
<pre><code>net.inet.ip.accept_sourceroute=0</code></pre>

Run the following commands to set the active kernel parameters:

<pre><code># sysctl -w net.inet.ip.accept_sourceroute=0</code></pre>


#### CIS Controls:

Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 3.2.2 Ensure ICMP redirects are not accepted (Scored)

#### Profile Applicability:

* Level 1 - Server
* Level 1 - Workstation

#### Description:
ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing devce to update your system routing tables. By setting the <code>net.inet.icmp.drop_redirect</code> sysctl to 1, the system will not accept any ICMP redirect messages, and therefore, won’t allow outsiders to update the system’s routing tables.

#### Rationale:
Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured.

#### Audit:
Run the following commands and verify output matches:

<pre><code># sysctl net.inet.icmp.drop_redirect
net.inet.icmp.drop_redirect: 1</code></pre>

#### Remediation:
Set the following parameters in <code>/etc/sysctl.conf</code>:

<pre><code>net.inet.icmp.drop_redirect=1</code></pre>
Run the following commands to set the active kernel parameters:

<pre><code># sysctl net.inet.icmp.drop_redirect=1</code></pre>

#### CIS Controls:

Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized operating systems and software.

## 3.2.3 Ensure broadcast ICMP requests are ignored (Scored)

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Setting <code>net.inet.icmp.bmcastecho</code> to 0 will cause the system to ignore all
ICMP echo and timestamp requests to broadcast and multicast addresses.

#### Rationale:
Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for
your network could be used to trick your host into starting (or participating) in a Smurf
attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast
messages with a spoofed source address. All hosts receiving this message and responding
would send echo-reply messages back to the spoofed address, which is probably not
routable. If many hosts respond to the packets, the amount of traffic on the network could
be significantly multiplied.

#### Audit:
Run the following commands and verify output matches:
<pre><code># sysctl net.inet.icmp.bmcastecho
net.inet.icmp.bmcastecho: 0</code></pre>


#### Remediation:
Set the following parameters in <code>/etc/sysctl.conf</code>:

<pre><code>net.inet.icmp.bmcastecho=0</code></pre>
Run the following commands to set the active kernel parameters:

<pre><code># sysctl net.inet.icmp.bmcastecho=0</code></pre>


#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 3.2.4 Ensure TCP SYN Cookies is enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
When <code>tcp.syncookies</code> is set, the kernel will handle TCP SYN packets normally until the
half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN
cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the
SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that
encodes the source and destination IP address and port number and the time the packet
was sent. A legitimate connection would send the ACK packet of the three way handshake
with the specially crafted sequence number. This allows the system to verify that it has
received a valid response to a SYN cookie and allow the connection, even though there is no
corresponding SYN in the queue.

#### Rationale:
Attackers use SYN flood attacks to perform a denial of service attacked on a system by
sending many SYN packets without completing the three way handshake. This will quickly
use up slots in the kernel's half-open connection queue and prevent legitimate connections
from succeeding. SYN cookies allow the system to keep accepting valid connections, even if
under a denial of service attack.

#### Audit:
Run the following commands and verify output matches:
<pre><code># sysctl net.inet.tcp.syncookies
net.inet.tcp.syncookies: 1</code></pre>

#### Remediation:
Set the following parameters in <code>/etc/sysctl.conf</code>:

<pre><code>net.inet.tcp.syncookies=1</code></pre>

Run the following commands to set the active kernel parameters:

<pre><code># sysctl net.inet.tcp.syncookies=1</code></pre>

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 3.2.5 Ensure IPv6 router advertisements are not accepted

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
This setting disables the system's ability to accept IPv6 router advertisements.

#### Rationale:
It is recommended that systems do not accept router advertisements as they could be
tricked into routing traffic to compromised machines. Setting hard routes within the
system (usually a single default route to a trusted router) protects the system from bad
routes.

#### Audit:
Run the following commands and verify output matches:
<pre><code># sysctl net.inet6.ip6.accept_rtadv
net.inet6.ip6.accept_rtadv: 0</code></pre>


#### Remediation:
Set the following parameters in <code>/etc/sysctl.conf</code>:

<pre><code>net.inet6.ip6.accept_rtadv=0</code></pre>

Run the following commands to set the active kernel parameters:

<pre><code># sysctl net.inet6.ip6.accept_rtadv=0</code></pre>

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.

# 3.3  Uncommon Network Protocols

The FreeBSD kernel modules support several network protocols that are not commonly used.
If these protocols are not needed, it is recommended that they be disabled in the kernel.
**Note:** This should not be considered a comprehensive list of uncommon network protocols,
you may wish to consider additions to those listed here for your environment.

# 3.4 Firewall Configuration

A firewall Provides defense against external and internal threats by refusing unauthorized
connections, to stop intrusion and provide a strong method of access control policy.
this section is intended only to ensure the resulting firewall rules are in place, not how they
are configured.

# 3.4.1 Ensure Firewall software is configured.

FreeBSD has three firewalls built into the base system: PF, IPFW, and IPFILTER, also known as IPF. FreeBSD also provides two traffic shapers for controlling bandwidth usage: altq(4) and dummynet(4). ALTQ has traditionally been closely tied with PF and dummynet with IPFW. Each firewall uses rules to control the access of packets to and from a FreeBSD system, although they go about it in different ways and each has a different rule syntax.

This benchmark will focus on using PF, IPFW is out of scope. 

## 3.4.1.1 Ensure PF service is enabled and running

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Ensure that PF service is enabled to protect your system

#### Rationale:
PF (Packet Filter) tool provides a dynamically managed firewall. PF is a complete, full-featured firewall that has optional support for ALTQ (Alternate Queuing), which provides Quality of Service. To use PF, its kernel module must be first loaded.

#### Audit:
Run the following command to verify that PF and PFlog are enabled:
<pre><code># service pflog onestatus
pflog is running as pid [PID].
# service pflog onestatus
Status: Enabled</code></pre>


#### Remediation:
Run the following commands to enable and start the PF firewall
<pre><code># sysrc pf_enable=yes
# sysrc pflog_enable=yes
# service pf start
# service pflog start
# pfctl -e
</code></pre>

#### Impact:
Changing firewall settings while connected over network can result in being locked out of
the system.

#### CIS Controls:
Version 7

9.4 Apply Host-based Firewalls or Port Filtering

Apply host-based firewalls or port filtering tools on end systems, with a default-deny
rule that drops all traffic except those services and ports that are explicitly allowed.

## 3.4.1.2 Create a PF Ruleset

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
PF will not start if it cannot find its ruleset configuration file. By default, FreeBSD does not ship with a ruleset and there is no <code>/etc/pf.conf</code> Example rulesets can be found in <code>/usr/share/examples/pf/</code>. The configuration file will need to be created and configured.

#### Rationale:
PF requires a ruleset configuration file to be written in order to run.

#### Audit:
Run the following command and verify that the ruleset adheres to company policy:
<pre><code># pfctl -s [ rules | nat | states ]</code></pre>

#### Remediation:
Create and edit <code>/etc/pf.conf</code> to adhere to company policy
<pre><code># touch /etc/pf.conf</code></pre>

#### Example:
The simplest possible ruleset is for a single machine that does not run any services and which needs access to one network, which may be the Internet. To create this minimal ruleset, edit <code>/etc/pf.conf</code> so it looks like this:
<pre><code>block in all
pass out all keep state</code></pre>

In this more complicated example, all traffic is blocked except for the connections initiated by this system for the seven specified TCP services and the one specified UDP service:
<pre><code>tcp_services = "{ ssh, smtp, domain, www, pop3, auth, pop3s }"
udp_services = "{ domain }"
block all
pass out proto tcp to any port $tcp_services keep state
pass proto udp to any port $udp_services keep state</code></pre>

Run the following command after every time <code>/etc/pf.conf</code> is edited to load the new ruleset:
<pre><code># pfctl -f /etc/pf.conf</code></pre>


#### References:
1. https://www.freebsd.org/doc/handbook/firewalls-pf.html

#### CIS Controls:

Version 7

9.4 Apply Host-based Firewalls or Port Filtering

Apply host-based firewalls or port filtering tools on end systems, with a default-deny
rule that drops all traffic except those services and ports that are explicitly allowed.

## 3.4.1.3 Ensure Only One Firewall is Enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
FreeBSD has three firewalls built into the base system: PF, IPFW, and IPFILTER, also known as IPF. FreeBSD also provides two traffic shapers for controlling bandwidth usage: altq(4) and dummynet(4). ALTQ has traditionally been closely tied with PF and dummynet with IPFW. Each firewall uses rules to control the access of packets to and from a FreeBSD system, although they go about it in different ways and each has a different rule syntax. Ensure that the system is only running one.

#### Rationale:
While FreeBSD has multiple firewall options, multiple firewalls could lead to confusion.

#### Audit:
Run the following command to verify that only PF and PFlog are enabled:

<pre><code># service ipfw onestatus
ipfw is not enabled
# service ipfilter </code></pre>


#### Remediation:
Depending on the results of the audit, start by stopping any additional firewall services:
<pre><code># service ipfw stop</code></pre>
or 
<pre><code># service ipfilter stop</pre></code>

Then remove any of the following entries from <code>/etc/rc.conf</code>
<pre><code>
firewall_enable="YES"
firewall_type="open"</code></pre>

or
<pre><code>
ipfilter_enable="YES"             
ipfilter_rules="/etc/ipf.rules"   
ipv6_ipfilter_rules="/etc/ipf6.rules" 
ipmon_enable="YES"                
ipmon_flags="-Ds"</code></pre>


#### CIS Controls:

Version 7

9.4 Apply Host-based Firewalls or Port Filtering

Apply host-based firewalls or port filtering tools on end systems, with a default-deny
rule that drops all traffic except those services and ports that are explicitly allowed.

# 4 Logging and Auditing

The items in this section describe how to configure logging, log monitoring, and auditing,
using tools included in most distributions. In addition to the local log files created by the steps in this section, it is also recommended
that sites collect copies of their system logs on a secure, centralized log server via an
encrypted connection. Not only does centralized logging help sites correlate events that
may be occurring on multiple systems, but having a second copy of the system log
information may be critical after a system compromise where the attacker has modified the
local log files on the affected system(s). If a log correlation system is deployed, configure it
to process the logs described in this section.

It is important that all logs described in this section be monitored on a regular basis and
correlated to determine trends. A seemingly innocuous entry in one log could be more
significant when compared to an entry in another log.

**Note on log file permissions:** There really isn't a "one size fits all" solution to the
permissions on log files. Many sites utilize group permissions so that administrators who
are in a defined security group, such as "wheel" do not have to elevate privileges to root in
order to read log files. Also, if a third party log aggregation tool is used, it may need to have
group permissions to read the log files, which is preferable to having it run setuid to root.
Therefore, there are two remediation and audit steps for log file permissions. One is for
systems that do not have a secured group method implemented that only permits root to
read the log files (<code>root:wheel 600</code>). The other is for sites that do have such a setup and are
designated as <code>root:securegrp 640</code> where securegrp is the defined security group (in some
cases wheel).



## 4.1.1 Ensure auditing is enabled
The capturing of system events provides system administrators with information to allow
them to determine if unauthorized access to their system is occurring

## 4.1.1.1 Ensure auditd is installed

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
auditd is the userspace component to the FreeBSD Auditing System. It's responsible for
writing audit records to the disk

#### Rationale:
The capturing of system events provides system administrators with information to allow
them to determine if unauthorized access to their system is occurring.

#### Audit:
Run the following command and verify the output:
<pre><code># ls /usr/sbin/auditd
/usr/sbin/auditd</code></pre>

#### Remediation:
Run the following command to Install auditd
<pre><code># pkg install auditd</code></pre>

#### CIS Controls:
Version 7

6.2 Activate audit logging
Ensure that local logging has been enabled on all systems and networking devices.

6.3 Enable Detailed Logging
Enable system logging to include detailed information such as an event source, date,
user, timestamp, source addresses, destination addresses, and other useful elements.

## 4.1.1.2 Ensure auditd service is enabled

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Turn on the <code>auditd</code> daemon to record system events.

#### Rationale:
The capturing of system events provides system administrators with information to allow
them to determine if unauthorized access to their system is occurring.

#### Audit:
Run the following command to verify auditd is enabled:
<pre><code># service auditd status
auditd is running as pid [PID].</code></pre>

Verify that <code>auditd</code> is running.

#### Remediation:
Add the following line <code>/etc/rc.conf</code>
<pre><code>auditd_enable="YES"</code></pre>
Run the following command to enable auditd:
<pre><code># service auditd start</code></pre>

#### Notes:
Additional methods of enabling a service exist. Consult your distribution documentation for
appropriate methods.

#### CIS Controls:
Version 7

6.2 Activate audit logging
Ensure that local logging has been enabled on all systems and networking devices.

6.3 Enable Detailed Logging
Enable system logging to include detailed information such as an event source, date,
user, timestamp, source addresses, destination addresses, and other useful elements.

## 4.1.1.4 Ensure auditd qsize is sufficient

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
The qsize is not defined by default

#### Rationale:
There is no limit by default, however, If a different qsize has been specified, auditd records may be lost and potential malicious activity could go undetected.

#### Audit:
Run the following command and verify there is either no output, or qsize has been set to an appropriate size for your organization:
<pre><code># grep qsize /etc/security/audit_control
qsize:8192</code></pre>

Recommended that this value be 8192 or larger.

#### Remediation:
Edit <code>/etc/security/audit_control</code> and add the following line:
<pre><code>qsize:8192</code></pre>


#### CIS Controls:
Version 7
6.2 Activate audit logging
Ensure that local logging has been enabled on all systems and networking devices.
6.3 Enable Detailed Logging
Enable system logging to include detailed information such as an event source, date, user, timestamp, source addresses, destination addresses, and other useful elements.

## 4.1.2 Configure Data Retention

When auditing, it is important to carefully configure the storage requirements for audit
logs. By default, auditd will max out the log files at 2MB and retain only 4 copies of them.
Older versions will be deleted. It is possible on a system that the 20 MBs of audit logs may
fill up the system causing loss of audit data. While the recommendations here provide
guidance, check your site policy for audit storage requirements.

## 4.1.2.1 Ensure audit log storage size is configured (Scored)

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Configure the maximum size of the audit log file. Once the log reaches the maximum size, it
will be rotated and a new log file will be started.

#### Rationale:
It is important that an appropriate size is determined for log files so that they do not impact
the system and audit data is not lost.

#### Audit:
Run the following command and ensure output is in compliance with site policy:
<pre><code># grep filesz: /etc/security/audit_control
filesz: [bytes]</code></pre>

#### Remediation:
Set the following parameter in <code>/etc/security/audit_control</code> in accordance with site policy:
<pre><code>filesz: [bytes]</code></pre>

#### Notes:

For convenience, the log size may be	expressed with suffix letters: B (Bytes), K (Kilobytes), M (Megabytes), or G (Gigabytes). For example, 2M is	the same as 2097152.

Other methods of log rotation may be appropriate based on site policy.

#### CIS Controls:
Version 7

6.4 Ensure adequate storage for logs

Ensure that all systems that store logs have adequate storage space for the logs
generated.

## 4.1.2.2 Ensure audit logs are not automatically deleted

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
The <code>expire-after</code> setting determines whent he audit log file will expire and be removed. This may be after a time period	has passed since the file was last written to	or when	the aggregate of all the trail files have reached a specified size or a combination of both. If no expire-after parameter is	given then audit log files will	not expire and be	removed	by the audit control system.

#### Rationale:
In high security contexts, the benefits of maintaining a long audit history exceed the cost of
storing the audit history.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep expire-after: /etc/security/audit_control</code></pre>
There should be no output.

#### Remediation:
Remove the following parameter in <code>/etc/security/audit_control</code>:
<pre><code>expire-after: [time]</code></pre>

#### CIS Controls:
Version 7

6.4 Ensure adequate storage for logs

Ensure that all systems that store logs have adequate storage space for the logs
generated.

## 4.1.2.3 Ensure system is disabled when audit logs are full

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
The auditd daemon can be configured to halt the system when the audit logs are full.

#### Rationale:
In high security contexts, the risk of detecting unauthorized access or nonrepudiation
exceeds the benefit of the system's availability.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep policy: /etc/security/audit_control
policy:ahlt</code></pre>
Other policy flags may be in use, ensure that <code>ahlt</code> is included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:ahlt</code></pre>


## 4.1.3 Ensure login and logout events are collected

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Monitor login and logout events. The parameters below track changes to files associated
with login/logout events. The file /var/log/faillog tracks failed events from login. The
file /var/log/lastlog maintain records of the last time a user successfully logged in.

#### Rationale:
Monitoring login/logout events could provide a system administrator with information
associated with brute force attacks against user logins.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:lo</code></pre>
Other policy flags may be in use, ensure that <code>lo</code> is included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:lo</code></pre>

#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:

Version 7

4.9 Log and Alert on Unsuccessful Administrative Account Login
Configure systems to issue a log entry and alert on unsuccessful logins to an
administrative account.

16.13 Alert on Account Login Behavior Deviation
Alert when users deviate from normal login behavior, such as time-of-day, workstation
location and duration.

## 4.1.4 Ensure events that modify the system's network environment are collected

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Record changes to network environment files or system calls. The below parameters
monitor Audit events related to network actions such as <code>connect(2)</code> and <code>accept(2)</code>.

#### Rationale:
Monitoring <code>connect(2)</code> and <code>accept(2)</code> will identify potential unauthorized changes
to host and domainname of a system. The changing could potentially break
security parameters that are set based on those actions. 

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:nt</code></pre>
Other policy flags may be in use, ensure that <code>nt</code> is included.


#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:nt</code></pre>

#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:
Version 7

5.5 Implement Automated Configuration Monitoring Systems

Utilize a Security Content Automation Protocol (SCAP) compliant configuration
monitoring system to verify all security configuration elements, catalog approved
exceptions, and alert when unauthorized changes occur.

##  4.1.5 Ensure discretionary access control permission modification events are collected

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Audit events where file attribute modification occurs, such as by <code>chown(8)</code>, <code>chflags(1)</code>, and <code>flock(2)</code>. This will monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. 

#### Rationale:
Monitoring for changes in file attributes could alert a system administrator to activity that
could indicate intruder activity or policy violation.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:fm</code></pre>
Other policy flags may be in use, ensure that <code>fm</code> is included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:fm</code></pre>


#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:

Version 7

5.5 Implement Automated Configuration Monitoring Systems

Utilize a Security Content Automation Protocol (SCAP) compliant configuration
monitoring system to verify all security configuration elements, catalog approved
exceptions, and alert when unauthorized changes occur.

## 4.1.6 Ensure unsuccessful unauthorized file access attempts are collected

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Monitor for unsuccessful attempts to access files. An audit log record will only be written if the user is a nonprivileged user or if it is not a Daemon event.

#### Rationale:
Failed attempts to open or create files could be an indication that an individual or
process is trying to gain unauthorized access to the system.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:-fw,-fc</code></pre>
Other policy flags may be in use, ensure that <code>-fw,-fc</code> are included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:-fw,-fc</code></pre>


#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:

Version 7

14.9 Enforce Detail Logging for Access or Changes to Sensitive Data

Enforce detailed audit logging for access to sensitive data or changes to sensitive data
(utilizing tools such as File Integrity Monitoring or Security Information and Event
Monitoring).

## 4.1.7 Ensure file deletion events by users are collected

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
Monitor the use of system calls associated with the deletion of files and file
attributes. 

#### Rationale:
Monitoring these calls from non-privileged users could provide a system administrator
with evidence that inappropriate removal of files and file attributes associated with
protected files is occurring. While this audit option will look at all events, system
administrators will want to look for specific privileged files that are being deleted or
altered.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:fd</code></pre>
Other policy flags may be in use, ensure that <code>fd</code> is included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:fd</code></pre>

#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:
Version 7

4.8 Log and Alert on Changes to Administrative Group Membership

Configure systems to issue a log entry and alert when an account is added to or removed
from any group assigned administrative privilege

## 4.1.8 Ensure system administrator actions are collected 

#### Profile Applicability:

* Level 2 - Server
* Level 2 - Workstation

#### Description:
Monitor the sudo log file. If the system has been properly configured to disable the use of
the su command and force all administrators to have to log in first and then use sudo to
execute privileged commands, then all administrator commands will be logged. Any time a command is executed, an audit event will be triggered.


#### Rationale:
Changes in the log indicate that an administrator has executed a command or
the log file itself has been tampered with. This allows administrators to verify if
unauthorized commands have been executed.

#### Audit:
Run the following command and verify output matches:
<pre><code># grep flags: /etc/security/audit_control
flags:ad</code></pre>
Other policy flags may be in use, ensure that <code>ad</code> is included.

#### Remediation:
Set the following parameters in <code>/etc/audit/auditd_control</code>:
<pre><code>policy:ad</code></pre>

#### Notes:
Reloading the auditd config to set active settings may require a system reboot.

#### CIS Controls:

Version 7

4.9 Log and Alert on Unsuccessful Administrative Account Login
Configure systems to issue a log entry and alert on unsuccessful logins to an
administrative account.

## 4.2 Configure Logging

Logging services should be configured to prevent information leaks and to aggregate logs
on a remote server so that they can be reviewed in the event of a system compromise and
ease log analysis.

## 4.2.1 Configure rsyslog

Generating and reading system logs is an important aspect of system administration. The information in system logs can be used to detect hardware and software issues as well as application and system configuration errors. This information also plays an important role in security auditing and incident response. Most system daemons and applications will generate log entries.

FreeBSD provides a system logger, <code>syslogd</code>, to manage logging. By default, <code>syslogd</code> is started when the system boots. This is controlled by the variable <code>syslogd_enable</code> in <code>/etc/rc.conf</code>. There are numerous application arguments that can be set using <code>syslogd_flags</code> in <code>/etc/rc.conf</code>. 

## 4.2.1.1 Ensure syslog Service is enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
By default <code>syslog</code> is started when the system boots, ensure that this is the case.

#### Rationale:
If the syslog service is not activated the system may lack
logging.

#### Audit:
Run the following command to verify syslog is enabled on boot:
<pre><code># grep syslogd_enable /etc/rc.conf
syslogd_enable="YES"</code></pre>

Verify result is "YES".

#### Remediation:
Edit <code>/etc/rc.conf</code> and add the following line:
<pre><code>syslogd_enable="YES"</code></pre>

#### Notes:
Additional methods of enabling a service exist. Consult your distribution documentation for
appropriate methods.

#### CIS Controls:
Version 7

6.2 Activate audit logging

Ensure that local logging has been enabled on all systems and networking devices.

6.3 Enable Detailed Logging

Enable system logging to include detailed information such as an event source, date,
user, timestamp, source addresses, destination addresses, and other useful elements.

## 4.2.1.2 Ensure syslog default file permissions are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
syslog will create logfiles that do not already exist on the system. This setting controls
what permissions will be applied to these newly created files.

#### Rationale:
It is important to ensure that log files have the correct permissions to ensure that sensitive
data is archived and protected.

#### Audit:
Run the following command to view a list of all log files, ensure they all are set to 640 or more restrictive.:
<pre><code># cat /etc/syslog.conf</code></pre>

#### Remediation:
Edit the <code>/etc/syslog.conf</code> <code>0640</code> or more restrictive:

#### References:
1. See the <code>syslog.conf(5)</code> man page for more information.

#### Notes:
You should also ensure this is not overridden with less restrictive settings in any
<code>/etc/syslog.d/*</code> conf file.

#### CIS Controls:

Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 4.2.1.3 Ensure logging is configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The /etc/syslog.conf file specifies rules for logging and
which files are to be used to log certain classes of messages.

#### Rationale:
A great deal of important security-related information is sent via syslog (e.g., successful
and failed su attempts, failed login attempts, root login attempts, etc.).

#### Audit:
Review the contents of the <code>/etc/rsyslog.conf</code> file to ensure
appropriate logging is set. In addition, run the following command and verify that the log
files are logging information:

<pre><code># cat /etc/syslog.conf</code></pre>

#### Remediation:
Edit the following lines in the /etc/rsyslog.conf as appropriate for your environment:

<pre><code># $FreeBSD$
*.err;kern.warning;auth.notice;mail.crit                /dev/console
*.notice;authpriv.none;kern.debug;lpr.info;mail.crit;news.err   /var/log/messages
security.*                                      /var/log/security
auth.info;authpriv.info                         /var/log/auth.log
mail.info                                       /var/log/maillog
lpr.info                                        /var/log/lpd-errs
ftp.info                                        /var/log/xferlog
cron.*                                          /var/log/cron
!-devd
*.=debug                                        /var/log/debug.log
*.emerg                                         *
#console.info                                   /var/log/console.log
#*.*                                            /var/log/all.log
#*.*                                            @loghost
# news.crit                                     /var/log/news/news.crit
# news.err                                      /var/log/news/news.err
# news.notice                                   /var/log/news/news.notice
# !devd
# *.>=info
!ppp
*.*                                             /var/log/ppp.log
!*</code></pre>
Run the following command to reload the syslogd configuration:
<pre><code># service syslogd restart</code></pre>

#### References:
1. See the syslog.conf(5) man page for more information.

#### CIS Controls:
Version 7


6.2 Activate audit logging
Ensure that local logging has been enabled on all systems and networking devices.

6.3 Enable Detailed Logging

Enable system logging to include detailed information such as an event source, date,
user, timestamp, source addresses, destination addresses, and other useful elements.

## 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>syslog</code> utility supports the ability to send logs it gathers to a remote log host running
<code>syslogd</code> or to receive messages from remote hosts, reducing administrative overhead.

#### Rationale:
Storing log data on a remote host protects log integrity from local attacks. If an attacker
gains root access on the local system, they could tamper with or remove log data that is
stored on the local system

#### Audit:
Review the <code>/etc/rc.conf</code> and verify that logs are
sent to a central host (where logserv.example.com is the name of your central log host):
<pre><code># grep syslogd /etc/rc.conf
syslogd_enable="YES"
syslogd_flags="-s -v -v"</code></pre>

<pre><code># grep "." /etc/syslog.conf
*.*		@logserv.example.com</code></pre>

#### Remediation:
Edit the <code>/etc/rc.conf</code> and add the following lines
<pre><code>syslogd_enable="YES"
syslogd_flags="-s -v -v"</code></pre>

Then edit <code>/etc/syslog.conf</code> and add the following line (where logserv.example.com is the name of your central log host):
<pre><code>*.*		          @logserv.example.com</code></pre>

Run the following command to reload the rsyslogd configuration:
<pre><code># service syslogd restart</code></pre>

#### References:
1. See the syslog.conf(5) man page for more information.

#### CIS Controls:
Version 7

6.6 Deploy SIEM or Log Analytic tool

Deploy Security Information and Event Management (SIEM) or log analytic tool for log
correlation and analysis.

6.8 Regularly Tune SIEM

On a regular basis, tune your SIEM system to better identify actionable events and
decrease event noise.

## 4.2.1.5 Ensure remote syslog messages are accepted on designated log hosts

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
By default, syslog does not listen for log messages coming in from remote systems. The remote hosts will have to be configured to accept logging information from other hosts.

#### Rationale:
The guidance in the section ensures that remote log hosts are configured to accept
syslog data from hosts within the specified domain and that those systems that are not
designed to be log hosts do not accept any remote syslog messages. This provides
protection from spoofed log data and ensures that system administrators are reviewing
reasonably complete syslog data in a central location.

#### Audit:
Run the following commands and verify the resulting lines on the designated log server (where logclient.example.com is the name of your remote system):

<pre><code># grep syslogd /etc/rc.conf
syslogd_enable="YES"
syslogd_flags="-a logclient.example.com -v -v"</code></pre>

<pre><code># grep +logclient /etc/syslog.conf
+logclient.example.com
*.*               /var/log/logclient.log</code></pre>



#### Remediation:
Edit the <code>/etc/rc.conf</code> and add the following lines (where logclient.example.com is the name of your remote system):

<pre><code>syslogd_enable="YES"
syslogd_flags="-a logclient.example.com -v -v"</code></pre>

Then edit <code>/etc/syslog.conf</code> and add the following lines:
<pre><code>+logclient.example.com
*.*               /var/log/logclient.log</code></pre>

Next, create the log file:

<pre><code>touch /var/log/logclient.log</code></pre>

Finally, syslogd should be restarted and verified:

#### References:
1. See the syslog(5) man page for more information.

#### Notes:
The $ModLoad imtcp line can have the .so extension added to the end of the module, or use
the full path to the module.

#### CIS Controls:
Version 7

9.2 Ensure Only Approved Ports, Protocols and Services Are Running

Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.




# Cron & Perodic

## 5.1 Ensure cron daemon is enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>cron</code> daemon is used to execute batch jobs on the system.

#### Rationale:
While there may not be user jobs that need to be run on the system, the system does have
maintenance jobs that may include security monitoring that have to run, and cron is used
to execute them.

#### Audit:
Run the the following command to verify <code>cron</code> is enabled:
<pre><code># service cron rcvar
# cron: Daemon to execute scheduled commands
#
cron_enable="YES"</code></pre>

Verify result of <code>cron_enable</code> is "YES".

#### Remediation:
Run the following command to enable <code>cron</code>:
<pre><code># service cron start</code></pre>

#### Notes:
Additional methods of enabling a service exist. Consult your distribution documentation for
appropriate methods.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.1.2 Ensure permissions on /etc/crontab are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/crontab</code> file is used by <code>cron</code> to control its own jobs. The commands in this item
make sure that <code>root</code> is the user and group owner of the file and that only the owner can
access the file.

#### Rationale:
This file contains information on what system jobs are run by cron. Write access to these
files could provide unprivileged users with the ability to elevate their privileges. Read
access to these files could provide users with the ability to gain insight on system jobs that
run on the system and could provide them a way to gain unauthorized privileged access.

#### Audit:
Run the following command and verify the the read/write permissions are correct, and the owner and owner group are set to root
and wheel:
<pre><code># ls -l /etc/crontab
-rw------- 1 root wheel [date and time] /etc/crontab</code></pre>

#### Remediation:
Run the following commands to set ownership and permissions on <code>/etc/crontab</code> :
<pre><code># chown root:wheel /etc/crontab
# chmod 600 /etc/crontab</code></pre>

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.1.3 Ensure permissions on /etc/cron.d are configured
#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/cron.d</code> directory contains system <code>cron</code> jobs that require more
granular control as to when they run. The files in this directory cannot be manipulated by
the <code>crontab</code> command, but are instead edited by system administrators using a text editor.
The commands below restrict read/write and search access to user and group root,
preventing regular users from accessing this directory.

#### Rationale:
Granting write access to this directory for non-privileged users could provide them the
means for gaining unauthorized elevated privileges. Granting read access to this directory
could give an unprivileged user insight in how to gain elevated privileges or circumvent
auditing controls.

#### Audit:
Run the following command and verify the the read/write permissions are correct, and the owner and owner group are set to root
and wheel:
<pre><code># ls -l /etc/cron.d
-rw------- 1 root wheel [date and time] /etc/cron.d</code></pre>

#### Remediation:
Run the following commands to set ownership and permissions on <code>/etc/crontab</code> :
<pre><code># chown root:wheel /etc/crontab
# chmod 600 /etc/cron.d</code></pre>

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.
  
 
## 5.1.4 Ensure at/cron/periodic are restricted to authorized users

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Configure <code>/etc/cron.d/cron.allow</code> and <code>/var/at/at.allow</code> to allow specific users to use these
services. If <code>/etc/cron.d/cron.allow</code> or <code>/var/at/at.allow</code> do not exist, then <code>/etc/cron.d/cron.deny</code> and <code>/var/at/at.deny</code> are checked. Any user not specifically defined in those files is allowed to
use at and <code>cron</code>. By removing the files, only users in <code>/etc/cron.d/cron.allow</code> and <code>/var/at/at.allow</code>
are allowed to use at and cron. Note that even though a given user is not listed in
<code>cron.allow</code> , cron jobs can still be run as that user. The <code>cron.allow</code> file only controls
administrative access to the crontab command for scheduling and modifying cron jobs.

#### Rationale:
On many systems, only the system administrator is authorized to schedule cron jobs. Using
the <code>cron.allow</code> file to control who can run cron jobs enforces this policy. It is easier to
manage an allow list than a deny list. In a deny list, you could potentially add a user ID to
the system and forget to add it to the deny files.

#### Audit:
Run the following commands and ensure <code>/etc/cron.d/cron.deny</code> and <code>/var/at/at.deny</code> do not exist:

<pre><code># stat /etc/cron.d/cron.deny
stat: /etc/cron.d/cron.deny: stat: No such file or directory</code></pre>

<pre><code># stat /var/at/at.deny
stat: /var/at/at.deny: stat: No such file or directory</code></pre>

Run the following command and verify Uid and Gid are both root and wheel and Access does not
grant permissions to group or other for both <code>/etc/cron.d/cron.allow</code> and <code>/var/at/at.allow</code> :

<pre><code># ls -l /etc/cron.d/cron.allow
-rw------- 1 root wheel [date and time] /etc/cron.d/cron.allow</code></pre>

<pre><code># ls -l /var/at/at.allow
-rw------- 1 root wheel [date and time] /etc/at/at.allow</code></pre>

#### Remediation:
Run the following commands to remove <code>/etc/cron.d/cron.deny</code> and <code>/var/at/at.deny</code> and create and
set permissions and ownership for <code>/etc/cron.d/cron.allow</code> and <code>/var/at/at.allow</code> :
<pre><code># rm /etc/cron.d/cron.deny
# rm /var/at/at.deny</code></pre>

<pre><code># touch /etc/cron.d/cron.allow
# touch /var/at/at.allow</code></pre>

<pre><code># chmod 600 /etc/cron.d/cron.allow
# chmod 600 /var/at/at.allow</code></pre>

<pre><code># chown root:wheel /etc/cron.d/cron.allow
# chown root:wheel /var/at/at.allow</code></pre>

#### CIS Controls:

Version 7

16 Account Monitoring and Control
Account Monitoring and Control



# **SSH**

## 5.2.1 Secure sshd_config:

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/ssh/sshd_config</code> file contains configuration specifications for sshd. The
command below sets the owner and group of the file to root.

#### Rationale:
The <code>/etc/ssh/sshd_config</code> file needs to be protected from unauthorized changes by nonprivileged users.

#### Audit:
Run the following command and verify Uid and Gid are root and wheel and Access does not
grant permissions to group or other:

<pre><code># ls -l /etc/ssh/sshd_config
-rw------- 1 root wheel [date and time] /etc/ssh/sshd_config</code></pre>


#### Remediation:
Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:
<pre><code># chown root:wheel /etc/ssh/sshd_config</code></pre>
<pre><code># chmod 600 /etc/ssh/sshd_config</code></pre>

#### CIS Controls:

Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software


## 5.2.2 Ensure SSH access is limited:

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:

There are several options available to limit which users and group can access the system
via SSH. It is recommended that at least one of the following options be leveraged:

<code>AllowUsers</code>

The <code>AllowUsers</code> variable gives the system administrator the option of allowing specific
users to ssh into the system. The list consists of space separated user names. Numeric user
IDs are not recognized with this variable. If a system administrator wants to restrict user
access further by only allowing the allowed users to log in from a particular host, the entry
can be specified in the form of user@host.

<code>AllowGroups</code>

The <code>AllowGroups</code> variable gives the system administrator the option of allowing specific
groups of users to ssh into the system. The list consists of space separated group names.
Numeric group IDs are not recognized with this variable.

<code>DenyUsers</code>

The <code>DenyUsers</code> variable gives the system administrator the option of denying specific users
to ssh into the system. The list consists of space separated user names. Numeric user IDs
are not recognized with this variable. If a system administrator wants to restrict user
access further by specifically denying a user's access from a particular host, the entry can
be specified in the form of user@host.

<code>DenyGroups</code>

The <code>DenyGroups</code> variable gives the system administrator the option of denying specific
groups of users to ssh into the system. The list consists of space separated group names.
Numeric group IDs are not recognized with this variable.

#### Rationale:

Restricting which users can remotely access the system via SSH will help ensure that only
authorized users access the system.

#### Audit:

Run the following commands:

<pre><code># sshd -T | grep -E allow
# sshd -T | grep -E deny</code></pre> 

Verify that the output matches at least one of the following lines:

<pre><code>AllowUsers [userlist]
  
AllowGroups [grouplist]
  
DenyUsers [userlist]
  
DenyGroups [grouplist]</code></pre>
  
  
  
#### Remediation:

Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:

<pre><code>AllowUsers [userlist]
  
AllowGroups [grouplist]
  
DenyUsers [userlist]
  
DenyGroups [grouplist]</code></pre>
  
  
#### CIS Controls:
Version 7
4.3 Ensure the Use of Dedicated Administrative Accounts
Ensure that all users with administrative account access use a dedicated or secondary
account for elevated activities. This account should only be used for administrative
activities and not internet browsing, email, or similar activities


## 5.2.3 Secure permissions on SSH private host key files:

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:

An SSH private key is one of two files used in SSH public key authentication. In this
authentication method, The possession of the private key is proof of identity. Only a private
key that corresponds to a public key will be able to authenticate successfully. The private
keys need to be stored and handled carefully, and no copies of the private key should be
distributed.

#### Rationale:
If an unauthorized user obtains the private SSH host key file, the host could be
impersonated


#### Audit:
Run the following command and verify the owner and group ID are set to root and wheel. The permissions should also be restricted to owner read/write only. 

<pre><code># ls -l ~/.ssh/id_rsa
-rw------- 1 root wheel [date and time] /root/.ssh/id_rsa
</code></pre>

#### Remediation:
Run the following commands to set ownership and permissions on the private SSH host key
files.
<pre><code># chown root:wheel ~/.ssh/id_rsa
# chmod 600 ~/.ssh/id_rsa</code></pre>

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.4 Ensure permissions on SSH public host key files

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
An SSH public key is one of two files used in SSH public key authentication. In this
authentication method, a public key is a key that can be used for verifying digital signatures
generated using a corresponding private key. Only a public key that corresponds to a
private key will be able to authenticate successfully.

#### Rationale:
If a public host key file is modified by an unauthorized user, the SSH service may be
compromised.

#### Audit:
Run the following command and verify the owner and group ID are set to root and wheel. The permissions should also grant everyone read access, but only the owner should have write permissions

<pre><code># ls -l ~/.ssh/id_rsa.pub
-rw-r--r-- 1 root wheel [date and time] /root/.ssh/id_rsa.pub</code></pre>

#### Remediation:
Run the following commands to set permissions and ownership on the SSH host public key
files

<pre><code># chown root:wheel ~/.ssh/id_rsa.pub
# chmod 644 ~/.ssh/id_rsa.pub</code></pre>

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.5 Ensure SSH LogLevel is appropriate

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:

<code>INFO</code> level is the basic level that only records login activity of SSH users. In many situations,
such as Incident Response, it is important to determine when a particular user was active
on a system. The logout record can eliminate those users who disconnected, which helps
narrow the field.

<code>VERBOSE</code> level specifies that login and logout activity as well as the key fingerprint for any
SSH key used for login will be logged. This information is important for SSH key
management, especially in legacy environments.

#### Rationale:
SSH provides several logging levels with varying amounts of verbosity. <code>DEBUG</code> is specifically
**not** recommended other than strictly for debugging SSH communications since it provides
so much data that it is difficult to identify important security information.

#### Audit:
Run the following command and verify that output matches:

<pre><code># sshd -T | grep loglevel
LogLevel VERBOSE
OR
loglevel INFO</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>LogLevel VERBOSE
OR
LogLevel INFO</code></pre>

#### Default Value:
LogLevel INFO


#### CIS Controls:
Version 7
6.2 Activate audit logging
Ensure that local logging has been enabled on all systems and networking devices.
6.3 Enable Detailed Logging
Enable system logging to include detailed information such as an event source, date,
user, timestamp, source addresses, destination addresses, and other useful elements.

## 5.2.6 Ensure SSH X11 forwarding is disabled

#### Profile Applicability:
* Level 1 - Workstation
* Level 2 - Server

#### Description:
The X11Forwarding parameter provides the ability to tunnel X11 traffic through the
connection to enable remote graphic connections.

#### Rationale:
Disable X11 forwarding unless there is an operational requirement to use X11 applications
directly. There is a small risk that the remote X11 servers of users who are logged in via
SSH with X11 forwarding could be compromised by other users on the X11 server. Note
that even if X11 forwarding is disabled, users can always install their own forwarders.

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep x11forwarding
X11Forwarding no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>X11Forwarding no</code></pre>

#### CIS Controls:
Version 7
9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

## 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>MaxAuthTries</code> parameter specifies the maximum number of authentication attempts
permitted per connection. When the login failure count reaches half the number, error
messages will be written to the <code>syslog</code> file detailing the login failure.

#### Rationale:
Setting the <code>MaxAuthTries</code> parameter to a low number will minimize the risk of successful
brute force attacks to the SSH server. While the recommended setting is 4, set the number
based on site policy.

#### Audit:
Run the following command and verify that output <code>MaxAuthTries</code> is 4 or less:
<pre><code># sshd -T | grep maxauthtries
MaxAuthTries 4</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>MaxAuthTries 4</code></pre>

#### Default Value:
MaxAuthTries 6

#### CIS Controls:
Version 7
16.13 Alert on Account Login Behavior Deviation
Alert when users deviate from normal login behavior, such as time-of-day, workstation
location and duration.

## 5.2.8 Ensure SSH IgnoreRhosts is enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>IgnoreRhosts</code> parameter specifies that <code>.rhosts</code> and <code>.shosts</code> files will not be used in
<code>RhostsRSAAuthentication</code> or <code>HostbasedAuthentication</code>.

#### Rationale:
Setting this parameter forces users to enter a password when authenticating with ssh.

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep ignorerhosts
IgnoreRhosts yes</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>IgnoreRhosts yes</code></pre>

#### Default Value:
IgnoreRhosts yes

#### CIS Controls:
Version 7
9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system

## 5.2.9 Ensure SSH HostbasedAuthentication is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>HostbasedAuthentication</code> parameter specifies if authentication is allowed through
trusted hosts via the user of <code>.rhosts</code>, or <code>/etc/hosts.equiv</code>, along with successful public
key client host authentication. This option only applies to SSH Protocol Version 2.


#### Rationale:
Even though the <code>.rhosts</code> files are ineffective if support is disabled in <code>/etc/pam.conf</code>,
disabling the ability to use <code>.rhosts</code> files in SSH provides an additional layer of protection.

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep hostbasedauthentication
HostbasedAuthentication no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>HostbasedAuthentication no</code></pre>

#### Default Value:
HostbasedAuthentication no

#### CIS Controls:
Version 7
16.3 Require Multi-factor Authentication
Require multi-factor authentication for all user accounts, on all systems, whether
managed onsite or by a third-party provider.

## 5.2.10 Ensure SSH root login is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation


#### Description:
The <code>PermitRootLogin</code> parameter specifies if the root user can log in using ssh. The default
is no.

#### Rationale:
Disallowing root logins over SSH requires system admins to authenticate using their own
individual account, then escalating to root via <code>sudo</code> or <code>su</code>. This in turn limits opportunity for
non-repudiation and provides a clear audit trail in the event of a security incident.

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep permitrootlogin
PermitRootLogin no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>PermitRootLogin no</code></pre>

#### Default Value:
PermitRootLogin no

#### CIS Controls:
Version 7
4.3 Ensure the Use of Dedicated Administrative Accounts
Ensure that all users with administrative account access use a dedicated or secondary
account for elevated activities. This account should only be used for administrative
activities and not internet browsing, email, or similar activities.

## 5.2.11 Ensure SSH PermitEmptyPasswords is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>PermitEmptyPasswords</code> parameter specifies if the SSH server allows login to accounts
with empty password strings.

#### Rationale:
Disallowing remote shell access to accounts that have an empty password reduces the
probability of unauthorized access to the system

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep permitemptypasswords
PermitEmptyPasswords no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>PermitEmptyPasswords no</code></pre>

#### Default Value:
PermitEmptyPasswords no

#### CIS Controls:
Version 7
16.3 Require Multi-factor Authentication
Require multi-factor authentication for all user accounts, on all systems, whether
managed onsite or by a third-party provider.

## 5.2.12 Ensure SSH PermitUserEnvironment is disabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>PermitUserEnvironment</code> option allows users to present environment options to the
<code>ssh</code> daemon.

#### Rationale:
Permitting users the ability to set environment variables through the SSH daemon could
potentially allow users to bypass security controls (e.g. setting an execution path that has
<code>ssh</code> executing trojan'd programs)

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep permituserenvironment
PermitUserEnvironment no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>PermitUserEnvironment no</code></pre>

#### Default Value:
PermitUserEnvironment no

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.13 Ensure SSH Idle Timeout Interval is configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The two options <code>ClientAliveInterval</code> and <code>ClientAliveCountMax</code> control the timeout of
<code>ssh</code> sessions. When the <code>ClientAliveInterval</code> variable is set, ssh sessions that have no
activity for the specified length of time are terminated. When the <code>ClientAliveMax</code>
variable is set, <code>sshd</code> will send client alive messages at every <code>ClientAliveInterval</code> interval.
When the number of consecutive client alive messages are sent with no response from the
client, the ssh session is terminated. For example, if the <code>ClientAliveInterval</code> is set to 15
seconds and the <code>ClientAliveMax</code> is set to 3, the client <code>ssh</code> session will be terminated
after 45 seconds of idle time.

#### Rationale:
Having no timeout value associated with a connection could allow an unauthorized user
access to another user's <code>ssh</code> session (e.g. user walks away from their computer and doesn't
lock the screen). Setting a timeout value at least reduces the risk of this happening..

While the recommended setting is 300 seconds (5 minutes), set this timeout value based on
site policy. The recommended setting for <code>ClientAliveCountMax</code> is 0. In this case, the client
session will be terminated after 5 minutes of idle time and no keepalive messages will be
sent.

#### Audit:
Run the following commands and verify <code>ClientAliveInterval</code> is between 1 and 300 and
<code>ClientAliveCountMax</code> is 3 or less:
<pre><code># sshd -T | grep clientaliveinterval
ClientAliveInterval 300
# sshd -T | grep clientalivecountmax
ClientAliveCountMax 0</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameters according to site policy:
<pre><code>ClientAliveInterval 300
ClientAliveCountMax 0</code></pre>

#### Default Value:
ClientAliveInterval 0

ClientAliveCountMax 3

#### CIS Controls:
Version 7
16.11 Lock Workstation Sessions After Inactivity
Automatically lock workstation sessions after a standard period of inactivity.

## 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>LoginGraceTime</code> parameter specifies the time allowed for successful authentication to
the SSH server. The longer the Grace period is the more open unauthenticated connections
can exist. Like other session controls in this session the Grace Period should be limited to
appropriate organizational limits to ensure the service is available for needed access.

#### Rationale:
Setting the <code>LoginGraceTime</code> parameter to a low number will minimize the risk of successful
brute force attacks to the SSH server. It will also limit the number of concurrent
unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set
the number based on site policy.

#### Audit:
Run the following command and verify that output LoginGraceTime is between 1 and 60:
<pre><code># sshd -T | grep logingracetime
LoginGraceTime 60</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>LoginGraceTime 1m</code></pre>

#### Default Value:
LoginGraceTime 2m

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.


## 5.2.15 Ensure SSH warning banner is configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>Banner</code> parameter specifies a file whose contents must be sent to the remote user
before authentication is permitted. By default, no banner is displayed.

#### Rationale:
Banners are used to warn connecting users of the particular site's policy regarding
connection. Presenting a warning message prior to the normal user login may assist the
prosecution of trespassers on the computer system.

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep banner
Banner /etc/issue.net</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>Banner /etc/issue.net</code></pre>

#### Default Value:
Banner none

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.16 Ensure SSH PAM is enabled

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will
enable PAM authentication using ChallengeResponseAuthentication and
PasswordAuthentication in addition to PAM account and session module processing for all
authentication types

#### Rationale:
When usePAM is set to yes, PAM runs through account and session types properly. This is
important if you want to restrict access to services based off of IP, time or other factors of
the account. Additionally, you can make sure users inherit certain environment variables
on login or disallow access to the server

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep -i usepam
usepam yes</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>UsePAM yes</code></pre>

#### Impact:
If UsePAM is enabled, you will not be able to run sshd(8) as a non-root user.

#### Default Value:
usePAM yes

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.17 Ensure SSH AllowTcpForwarding is disabled

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:
SSH port forwarding is a mechanism in SSH for tunneling application ports from the client
to the server, or servers to clients. It can be used for adding encryption to legacy
applications, going through firewalls, and some system administrators and IT professionals
use it for opening backdoors into the internal network from their home machines

#### Rationale:
Leaving port forwarding enabled can expose the organization to security risks and backdoors.

SSH connections are protected with strong encryption. This makes their contents invisible
to most deployed network monitoring and traffic filtering solutions. This invisibility carries
considerable risk potential if it is used for malicious purposes such as data exfiltration.
Cybercriminals or malware could exploit SSH to hide their unauthorized communications,
or to exfiltrate stolen data from the target network

#### Audit:
Run the following command and verify that output matches:
<pre><code># sshd -T | grep -i allowtcpforwarding
AllowTcpForwarding no</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>AllowTcpForwarding no</code></pre>

#### Impact:
SSH tunnels are widely used in many corporate environments that employ mainframe
systems as their application backends. In those environments the applications themselves
may have very limited native support for security. By utilizing tunneling, compliance with
SOX, HIPAA, PCI-DSS, and other standards can be achieved without having to modify the
applications.

#### Default Value:
AllowTcpForwarding yes

#### CIS Controls:
Version 7
9.2 Ensure Only Approved Ports, Protocols and Services Are Running
Ensure that only network ports, protocols, and services listening on a system with
validated business needs, are running on each system.

## 5.2.18 Ensure SSH MaxStartups is configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>MaxStartups</code> parameter specifies the maximum number of concurrent unauthenticated
connections to the SSH daemon.

#### Rationale:
To protect a system from denial of service due to a large number of pending authentication
connection attempts, use the rate limiting function of <code>MaxStartups</code> to protect availability of
sshd logins and prevent overwhelming the daemon.

#### Audit:
Run the following command and verify that output <code>MaxStartups</code> is 10:30:60 or matches
site policy:
<pre><code># sshd -T | grep -i maxstartups
# maxstartups 10:30:60</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>maxstartups 10:30:60</code></pre>

#### Default Value:
MaxStartups 10:30:100

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.2.19 Ensure SSH MaxSessions is set to 4 or less

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>MaxSessions</code> parameter specifies the maximum number of open sessions permitted
from a given connection.

#### Rationale:
To protect a system from denial of service due to a large number of concurrent sessions,
use the rate limiting function of <code>MaxSessions</code> to protect availability of sshd logins and
prevent overwhelming the daemon.

#### Audit:
Run the following command and verify that output <code>MaxSessions</code> is 4 or less, or matches site
policy:
<pre><code># sshd -T | grep -i maxsessions
maxsessions 4</code></pre>

#### Remediation:
Edit the <code>/etc/ssh/sshd_config</code> file to set the parameter as follows:
<pre><code>MaxSessions 4</code></pre>

#### Default Value:
MaxSessions 10


#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

# 5.4 PAM and Password Settings

## 5.4.1 Ensure password creation requirements are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>pam_passwdqc.so</code> module checks the strength of passwords. It performs checks such
as making sure a password is not a dictionary word, it is a certain length, contains a mix of
characters (e.g. alphabet, numeric, other) and more. The following are definitions of the
<code>pam_passwdqc.so</code> options.

* <code>min=N0,N1,N2,N3,N4</code>

   <code>(min=disabled,24,12,8,7)</code> The minimum allowed password lengths for
	 different kinds of	passwords/passphrases.	The keyword disabled
	 can be used to disallow passwords of a given kind regardless of
	 their length.  Each subsequent number is required to be no	larger
	 than the preceding	one.

   <code>N0</code>	is used	for passwords consisting of characters from one	char-
	 acter class only.	The character classes are: digits, lower-case
	 letters, upper-case letters, and other characters.	 There is also
	 a special class for non-ASCII characters which could not be clas-
	 sified, but are assumed to	be non-digits.

   <code>N1</code>	is used	for passwords consisting of characters from two	char-
	 acter classes, which do not meet the requirements for a
	 passphrase.

	 <code>N2</code>	is used	for passphrases.  A passphrase must consist of suffi-
	 cient words.

	 <code>N3</code>	and <code>N4</code> are used	for passwords consisting of characters from
	 three and four character classes, respectively.

	 When calculating the number of character classes, upper-case let-
	 ters used as the first character and digits used as the last
	 character of a password are not counted.


* <code>try_first_pass</code>

   Retrieve the password from a previous stacked PAM module. If
   not available, then prompt the user for a password.

* <code>retry=3</code> 
    Allow 3 tries before sending back a failure.

Strong passwords protect systems from being hacked through brute force methods. To ensure at least 4 classes of characters are used to enforce complex passwords.

#### Audit:
Verify password creation requirements conform to organization policy:

Run the following command and verify that retry conforms to organization policy.
<pre><code># grep pam_passwdqc.so /etc/pam.d/passwd</code></pre>
Output should be similar to:

<pre><code>password        requisite       pam_passwdqc.so         min=disabled,disabled,disabled,disabled,14 enforce=everyone</code></pre>


#### Remediation:
Edit the file <code>/etc/pam.d/passwd</code> and add or modify the following line for to ensur
password length and complexity conform to site policy

<pre><code>password        requisite       pam_passwdqc.so         min=disabled,disabled,disabled,disabled,14 enforce=everyone</code></pre>


#### Notes:
all default authselect profiles have pam_pwquality enabled with the expectation that
options will be specified in pwquality.conf

#### CIS Controls:
Version 7

4.4 Use Unique Passwords
Where multi-factor authentication is not supported (such as local administrator, root, or
service accounts), accounts will use passwords that are unique to that system

## 5.4.2 Ensure password hashing algorithm is SHA-512

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The commands below ensure password encryption is in <code>sha512</code> (a much stronger
hashing algorithm). All existing accounts will need to perform a password change to
upgrade the stored hashes to the new algorithm.

#### Rationale:
The <code>SHA-512</code> algorithm provides much stronger hashing than MD5, thus providing
additional protection to the system by increasing the level of effort for an attacker to
successfully determine passwords.

Note that these change only apply to accounts configured on the local system.

#### Audit:
Verify password hashing algorithm is <code>sha512</code>. This setting is configured with the
<code>passwd_format</code> <code>sha512</code> option found in <code>/etc/login.conf</code>

Run the following command:
<pre><code># grep -E passwd_format /etc/login.conf</code></pre>

The output should be similar to:

<pre><code>:passwd_format=sha512:\</code></pre>

#### Remediation:
Set password hashing algorithm to sha512. Modify or enable the <code>passwd_format</code> lines in the <code>/etc/login.conf</code>file for each user group.

<pre><code>:passwd_format=sha512:\</code></pre>

Than run the following command:

<pre><code># cap_mkdb /etc/login.conf</code></pre>

#### Notes:

Additional module options may be set, recommendation only covers those listed here.
If it is determined that the password algorithm being used is not <code>SHA-512</code>, once it is
changed, it is recommended that all user ID's be immediately expired and forced to change
their passwords on next login. To accomplish that, the following commands can be used.
Any system accounts that need to be expired should be carefully done separately by the
system administrator to prevent any potential problems.

<pre><code># awk -F: '( $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.conf)"' && $1 !=
"nfsnobody" ) { print $1 }' /etc/passwd | xargs -n 1 chage -d 0</code></pre>

#### CIS Controls:
Version 7

16.4 Encrypt or Hash all Authentication Credentials
Encrypt or hash with a salt all authentication credentials when stored

## 5.4.3 Ensure password reuse is limited

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
<code>pam_passwdqc</code> module can be checked to ensure that users are not recycling recent passwords.The passwords are considered	to be similar when there is a	sufficiently long common substring and the new pass-word with the substring removed would be weak.

#### Rationale:
Forcing users not to reuse their past asswords make it less likely that an attacker will be
able to guess the password.
Note that these change only apply to accounts configured on the local system.

#### Audit:
Run the following command and verify that the similar flag is set to deny:
<pre><code># grep similar= /etc/pam.d/passwd
password   requisite   pam_passwdqc.so   similar=deny</code></pre>


#### Remediation:
Set remembered password history to conform to site policy.
Edit <code>/etc/pam.d/passwd</code> and add the following line:
<pre><code>password   requisite   pam_passwdqc.so   similar=deny</code></pre>


#### Notes:
Additional module options may be set, recommendation only covers those listed here.

#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control



# User accounts & environment
This section provides guidance on setting up secure defaults for system and user accounts
and their environment.

## 5.5.1.1 Ensure password expiration is 365 days or less

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>passwordtime</code> parameter in <code>/etc/login.conf</code> allows an administrator to force
passwords to expire once they reach a defined age. It is recommended that the
<code>passwordtime</code> parameter be set to less than or equal to 365 days.

#### Rationale:
The window of opportunity for an attacker to leverage compromised credentials or
successfully compromise credentials via an online brute force attack is limited by the age of
the password. Therefore, reducing the maximum age of a password also reduces an
attacker's window of opportunity.

#### Audit:
Run the following command and verify <code>passwordtime</code> conforms to site policy (no more
than 365 days):

<pre><code># grep passwordtime /etc/login.conf
:passwordtime=365d:\</code></pre>

Run the following command and Review list of users and <code>passwordtime</code> to verify that all
users' <code>passwordtime</code> conforms to site policy (no more than 365 days):

<pre><code># grep -E '^[^:]+:[^!*]' /etc/master.passwd | cut -d: -f1,5
[user]:[passwordtime]
</code></pre>

#### Remediation:
Set the <code>passwordtime</code> parameter for each user group to conform to site policy in <code>/etc/login.conf</code> :
<pre><code>:passwordtime=365d</code></pre>
Modify user parameters for all users with a password set to match:
<pre><code># pw usermod -e 365 [user]</code></pre>
After the change, run the following command:
<pre><code># cap_mkdb /etc/login.conf</code></pre>

#### Notes:
Note: A value of -1 will disable password expiration. Additionally the password expiration
must be greater than the minimum days between password changes or users will be unable
to change their password.

#### CIS Controls:
Version 7

4.4 Use Unique Passwords
Where multi-factor authentication is not supported (such as local administrator, root, or
service accounts), accounts will use passwords that are unique to that system.

## 5.5.1.2 Ensure password expiration warning days is 7 or more

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>warnpassword</code> parameter in <code>/etc/login.conf</code> allows an administrator to notify users
that their password will expire in a defined number of days. It is recommended that the
<code>warnpassword</code> parameter be set to 7 or more days.

#### Rationale:
Providing an advance warning that a password will be expiring gives users time to think of
a secure password. Users caught unaware may choose a simple password or write it down
where it may be discovered.

#### Audit:
Run the following command and verify <code>warnpassword</code> for each user group conforms to site policy (No less than
7 days) and is enabled:

<pre><code># grep warnpassword /etc/login.conf
:warnpassword=7d:\</code></pre>


#### Remediation:
Set the <code>warnpassword</code> parameter to 7 in <code>/etc/login.conf</code> and ensure it is enabled for each user group :
<pre><code>warnpassword=7d</code></pre>

Then run the following command:
<pre><code># cap_mkdb /etc/login.conf</code></pre>


#### CIS Controls:
Version 7

4.4 Use Unique Passwords

Where multi-factor authentication is not supported (such as local administrator, root, or
service accounts), accounts will use passwords that are unique to that system.

## 5.5.1.3 Ensure all users last password change date is in the past

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
All users should have a password change date in the past.

#### Rationale:
If a users recorded password change date is in the future then they could bypass any set password expiration.

#### Audit:
Run the following command and verify each user's password expirory date:
<pre><code># pw usershow -P -a</code></pre>

#### Remediation:
Investigate any users with a password change date in the future and correct them. Locking the account, expiring the password, or resetting the password manually may be appropriate.

#### CIS Controls:
Version 7

4.4 Use Unique Passwords

Where multi-factor authentication is not supported (such as local administrator, root, or service accounts), accounts will use passwords that are unique to that system.

## 5.5.2 Ensure system accounts are secured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell.

#### Rationale:
It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the nologin shell. This prevents the account from potentially being used to run any commands.

#### Audit:
Run the following commands and verify non-user accounts (excluding <code>root</code> and <code>toor</code> have a dissabled password and are set to the <code>nologin</code> shell:
<pre><code># cat /etc/passwd</code></pre>

#### Example:

<pre><code>
git_daemon:*:964:964::0:0:git daemon:/nonexistent:/usr/sbin/nologin
pulse:*:563:563::0:0:PulseAudio System User:/nonexistent:/usr/sbin/nologin
polkit:*:562:562::0:0:PolicyKit User:/nonexistent:/usr/sbin/nologin
haldaemon:*:560:560::0:0:HAL Daemon User:/nonexistent:/usr/sbin/nologin
webcamd:*:145:145::0:0:Webcamd user:/var/empty:/usr/sbin/nologin</code></pre>

The <code>*</code> symbol in the 2nd field is the disabled password, and note that they are all nologin shell.

#### Remediation:
Set the shell for any accounts returned by the audit to nologin:
<pre><code># chsh -s /usr/sbin/nologin [user]</code></pre>


## 5.5.3 Ensure default user shell timeout is 900 seconds or less

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The default <code>TMOUT</code> determines the shell timeout for users. The <code>TMOUT</code> value is measured in
seconds.

#### Rationale:
Having no timeout value associated with a shell could allow an unauthorized user access to
another user's shell session (e.g. user walks away from their computer and doesn't lock the
screen). Setting a timeout value at least reduces the risk of this happening.

#### Audit:
Run the following commands and verify the returned TMOUT line is 900 or less

<pre><code># grep "^TMOUT" /etc/profile
readonly TMOUT=900 ; export TMOUT
</code></pre>

#### Remediation:
Edit the <code>/etc/profile</code> file (and the appropriate
files for any other shell supported on your system) and add or edit any umask parameters
as follows:
<pre><code>readonly TMOUT=900 ; export TMOUT</code></pre>
Note that setting the value to readonly prevents unwanted modification during runtime.

#### Notes:
The audit and remediation in this recommendation only applies to the <code>sh</code>. If other shells
are supported on the system, it is recommended that their configuration files also are
checked. Other methods of setting a timeout exist for other shells not covered here.
Ensure that the timeout conforms to your local policy.

#### CIS Controls:
Version 7

16.11 Lock Workstation Sessions After Inactivity
Automatically lock workstation sessions after a standard period of inactivity.

## 5.5.4 Ensure default group for the root account is GID 0

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>pw</code> command can be used to specify which group the root user belongs to. This
affects permissions of files that are created by the root user.

#### Rationale:
Using <code>GID 0</code> for the <code>root</code> account helps prevent <code>root</code> -owned files from accidentally
becoming accessible to non-privileged users.

#### Audit:
Run the following command and verify the result is 0 :
<pre><code># grep "^root:" /etc/passwd | cut -f4 -d:
0</code></pre>

#### Remediation:
Run the following command to set the root user default group to GID 0 :
<pre><code># pw usermod root -g 0</code></pre>

##### CIS Controls:
Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 5.5.5 Ensure default user umask is 027 or more restrictive

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The default <code>umask</code> determines the permissions of files created by users. The user creating
the file has the discretion of making their files and directories readable by others via the
chmod command. Users who wish to allow their files and directories to be readable by
others by default may choose a different default umask by inserting the umask command
into the standard shell configuration files ( <code>.profile</code> and <code>.cshrc</code>) in their home
directories.

#### Rationale:
Setting a very secure default value for <code>umask</code> ensures that users make a conscious choice
about their file permissions. A default <code>umask</code> setting of <code>077</code> causes files and directories
created by users to not be readable by any other user on the system. A <code>umask</code> of <code>027</code> would
make files and directories readable by users in the same Unix group, while a <code>umask</code> of <code>022</code>
would make files readable by every user on the system.

#### Audit:
Run the following commands and verify all umask lines returned are 027 or more
restrictive.
<pre><code># grep "umask" /etc/profile ~/.cshrc /etc/profile
umask 027</code></pre>

#### Remediation:
Edit the <code>/etc/profile</code> and <code>~/.cshrc files</code> (and the appropriate
files for any other shell supported on your system) and add or edit any <code>umask</code> parameters
as follows:
<pre><code>umask 027</code></pre>

#### Notes:
The audit and remediation in this recommendation apply to <code>sh</code> and <code>tcsh</code>. If other shells
are supported on the system, it is recommended that their configuration files also are
checked.

Other methods of setting a default user <code>umask</code> exist however the shell configuration files
are the last run and will override other settings if they exist therefor our recommendation
is to configure in the shell configuration files. If other methods are in use in your
environment they should be audited and the shell configs should be verified to not
override.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

13 Data Protection
Data Protection

## 5.5.6 Ensure root login is restricted to system console

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The file /etc/ttys contains a list of valid terminals that may be logged into directly by root.

#### Rationale:
Since the system console has special properties to handle emergency situations, it is
important to ensure that the console is in a physically secure location and that
unauthorized consoles have not been defined.

#### Audit:
<pre><code># cat /etc/ttys</code></pre>

#### Remediation:
Remove entries for any consoles that are not in a physically secure location. This can be done by 
changing the status of those consoles from secure to insecure.

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software

## 5.5.7 Ensure access to the su command is restricted

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>su</code> command allows a user to run a command or shell as another user. Normally, the <code>su</code> command can be executed by any user. By uncommenting the
<code>pam_wheel.so</code> statement in <code>/etc/pam.d/su</code> , the <code>su</code> command will only allow users in the
wheel group to execute <code>su</code> .

#### Rationale:
Restricting the use of <code>su</code>, provides system administrators better
control of the escalation of user privileges to execute privileged commands. 

#### Audit:
Run the following command and verify output includes matching line:
<pre><code># grep pam_group.so /etc/pam.d/su
auth requisite pam_group.so no_warn group=wheel root_only fail_safe ruser</code></pre>

Run the following command and verify users in wheel group match site policy. If no users
are listed, only root will have access to <code>su</code>.
<pre><code># grep wheel /etc/group
wheel:x:0:root,[user list]</code></pre>

#### Remediation:
Add the following line to the <code>/etc/pam.d/su</code> file:
<pre><code>auth requisite pam_group.so no_warn group=wheel root_only fail_safe ruser</code></pre>

Create a comma separated list of users in the wheel statement in the <code>/etc/group</code> file:
<pre><code>wheel:x:<GID>:root,[user list]</code></pre>
Example:
<pre><code>wheel:x:10:root,user1,user2,user3</code></pre>

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.


# File System Permissions

## 6.1.1 Audit system file permissions

#### Profile Applicability:
* Level 2 - Server
* Level 2 - Workstation

#### Description:



#### Rationale:
It is important to confirm that packaged system files and directories are maintained with
the permissions they were intended to have from the OS vendor.

#### Audit:
Run the following command to review all installed packages. Note that this may be very
time consuming and may be best scheduled via the cron utility. It is recommended that the
output of this command be redirected to a file that can be reviewed later.

<pre><code># pkg check -s > <filename></code></pre>

#### Remediation:
Correct any discrepancies found and rerun the audit until output is clean or risk is
mitigated or accepted.


#### Notes:
Since packages and important files may change with new updates and releases, it is
recommended to verify everything, not just a finite list of files. This can be a time
consuming task and results may depend on site policy therefore it is not a scorable
benchmark item, but is provided for those interested in additional security measures.
Some of the recommendations of this benchmark alter the state of files audited by this
recommendation. The audit command will alert for all changes to a file permissions even if
the new state is more secure than the default.

#### CIS Controls:
Version 7
14.6 Protect Information through Access Control Lists
Protect all information stored on systems with file system, network share, claims,
application, or database specific access control lists. These controls will enforce the
principle that only authorized individuals should have access to the information based on
their need to access the information as a part of their responsibilities.

## 6.1.2 Ensure permissions on /etc/passwd are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/passwd</code> file contains user account information that is used by many system
utilities and therefore must be readable for these utilities to operate.

#### Rationale:
It is critical to ensure that the <code>/etc/passwd</code> file is protected from unauthorized write
access. Although it is protected by default, the file permissions could be changed either
inadvertently or through malicious actions.

#### Audit:
Run the following command and verify the the read/write permissions are correct, and the owner and owner group are set to root and wheel:
<pre><code># ls -l /etc/passwd
-rw-r--r-- 1 root wheel [date and time] /etc/passwd</code></pre>

#### Remediation:
Run the following command to set permissions on /etc/passwd :
<pre><code># chown root:wheel /etc/passwd
# chmod 644 /etc/passwd</code></pre>

#### CIS Controls:
Version 7
16.4 Encrypt or Hash all Authentication Credentials
Encrypt or hash with a salt all authentication credentials when stored.

## 6.1.3 Ensure permissions on /etc/master.passwd are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/master.passwd</code> file is used to store the information about user accounts that is critical to
the security of those accounts, such as the hashed password and other security information.

#### Rationale:
If attackers can gain read access to the <code>/etc/master.passwd</code> file, they can easily run a password 
cracking program against the hashed password to break it. Other security information that
is stored in the <code>/etc/master.passwd</code> file (such as expiration) could also be useful to subvert the
user accounts.

#### Audit:
Run the following command and verify the the read/write permissions are correct, and the owner and owner group are set to root and wheel:

<pre><code># ls -l /etc/master.passwd
-rw-r----- root wheel [date and time] /etc/master.passwd</code></pre>

#### Remediation:
Run the one of the following chown commands as appropriate and the chmod to set
permissions on /etc/shadow :
<pre><code># chown root:wheel /etc/master.passwd
# chmod 640 /etc/master.passwd</code></pre>

#### CIS Controls:
Version 7
16.4 Encrypt or Hash all Authentication Credentials
Encrypt or hash with a salt all authentication credentials when stored.

## 6.1.4 Ensure permissions on /etc/group are configured

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The <code>/etc/group</code> file contains a list of all the valid groups defined in the system. The
command below allows read/write access for root and read access for everyone else.

#### Rationale:
The <code>/etc/group</code> file needs to be protected from unauthorized changes by non-privileged
users, but needs to be readable as this information is used with many non-privileged programs.

#### Audit:
Run the following command and verify the the read/write permissions are correct, and the owner and owner group are set to root and wheel:
<pre><code># ls -l /etc/group
-rw-r--r-- 1 root wheel [date and time] /etc/group</code></pre>

#### Remediation:
Run the following command to set permissions on <code>/etc/group</code> :
<pre><code># chown root:wheel /etc/group
# chmod 644 /etc/group</code></pre>

#### CIS Controls:
Version 7
16.4 Encrypt or Hash all Authentication Credentials
Encrypt or hash with a salt all authentication credentials when stored.

## 6.1.5 Ensure no world writable files exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
FreeBSD-based systems support variable settings to control access to files. World writable files
are the least secure. See the chmod(1) man page for more information.

#### Rationale:
Data in world-writable files can be modified and compromised by any user on the system.
World writable files may also indicate an incorrectly written script or program that could
potentially be the cause of a larger compromise to the system's integrity.

#### Audit:
Run the following command and verify no files are returned:
<pre><code># df -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002</code></pre>


#### Remediation:
Removing write access for the "other" category ( chmod o-w [ filename ] ) is advisable, but
always consult relevant vendor documentation to avoid breaking any application
dependencies on a given file.
  
#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.

13 Data Protection

Data Protection

## 6.1.6 Ensure no unowned files or directories exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Sometimes when administrators delete users from the password file they neglect to
remove all files owned by those users from the system.

#### Rationale:
A new user who is assigned the deleted user's user ID or group ID may then end up
"owning" these files, and thus have more access on the system than was intended.

#### Audit:
Run the following command and verify no files are returned:
<pre><code># find / -nouser</code></pre>

#### Remediation:
Locate files that are owned by users or groups not listed in the system configuration files,
and reset the ownership of these files to some active user on the system as appropriate.

#### CIS Controls:
Version 7
13.2 Remove Sensitive Data or Systems Not Regularly Accessed by Organization
Remove sensitive data or systems not regularly accessed by the organization from the
network. These systems shall only be used as stand alone systems (disconnected from the
network) by the business unit needing to occasionally use the system or completely
virtualized and powered off until needed.

## 6.1.7 Ensure no ungrouped files or directories exist


#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Sometimes when administrators delete groups from the password file they neglect to
remove all files owned by those groups from the system.

#### Rationale:
A new user who is assigned the deleted user's user ID or group ID may then end up
"owning" these files, and thus have more access on the system than was intended.

#### Audit:
Run the following command and verify no files are returned:
<pre><code># find / -nogroup</code></pre>

#### Remediation:
Locate files that are owned by users or groups not listed in the system configuration files,
and reset the ownership of these files to some active user on the system as appropriate.

#### CIS Controls:
Version 7
13.2 Remove Sensitive Data or Systems Not Regularly Accessed by Organization
Remove sensitive data or systems not regularly accessed by the organization from the
network. These systems shall only be used as stand alone systems (disconnected from the
network) by the business unit needing to occasionally use the system or completely
virtualized and powered off until needed.

## 6.1.8 Audit SUID executables

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The owner of a file can set the file's permissions to run with the owner's or group's
permissions, even if the user running the program is not the owner or a member of the
group. The most common reason for a SUID program is to enable users to perform
functions (such as changing their password) that require root privileges.

#### Rationale:
There are valid reasons for SUID programs, but it is important to identify and review such
programs to ensure they are legitimate.

#### Audit:
Run the following command to list SUID files:
<pre><code># find / -perm -4000 -print</code></pre>


#### Remediation:
Ensure that no rogue SUID programs have been introduced into the system. Review the
files returned by the action in the Audit section and confirm the integrity of these binaries.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 6.1.9 Audit SGID executables

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The owner of a file can set the file's permissions to run with the owner's or group's
permissions, even if the user running the program is not the owner or a member of the
group. The most common reason for a SGID program is to enable users to perform
functions (such as changing their password) that require root privileges.

#### Rationale:
There are valid reasons for SGID programs, but it is important to identify and review such
programs to ensure they are legitimate.  Review the files returned by the action in the audit
section and check to see if system binaries have a different md5 checksum than that of
the package. This is an indication that the binary may have been replaced.

#### Audit:
Run the following command to list SGID files:
<pre><code># find / -perm -2000 -print</code></pre>


#### Remediation:
Ensure that no rogue SGID programs have been introduced into the system. Review the
files returned by the action in the Audit section and confirm the integrity of these binaries.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.



# User and Group Settings

## 6.2.1 Ensure password fields are not empty

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
An account with an empty password field means that anybody may log in as that user
without providing a password.

#### Rationale:
All accounts must have passwords or be locked to prevent the account from being used by
an unauthorized user.

#### Audit:
Run the following command and verify that no output is returned:
<pre><code># awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/master.passwd</code></pre>

#### Remediation:
If any accounts in the <code>/etc/master.passwd</code> file do not have a password, run the following command
to lock the account until it can be determined why it does not have a password:

<pre><code># passwd -l [username]</code></pre>
  
Also, check to see if the account is logged in and investigate what it is being used for to
determine if it needs to be forced off.

#### CIS Controls:
Version 7
4.4 Use Unique Passwords
Where multi-factor authentication is not supported (such as local administrator, root, or
service accounts), accounts will use passwords that are unique to that system.

## 6.2.2 Ensure no legacy “+” entries exist in /etc/passwd

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The character + in various files used to be markers for systems to insert data from NIS
maps at a certain point in a system configuration file. These entries are no longer required
on most systems, but may exist in files that have been imported from other platforms.

#### Rationale:
These entries may provide an avenue for attackers to gain privileged access on the system.

#### Audit:
Run the following command and verify that no output is returned:
<pre><code># grep '^\+:' /etc/passwd</code></pre>

#### Remediation:
Remove any legacy '+' entries from /etc/passwd if they exist.

#### CIS Controls:
Version 7
16.2 Configure Centralized Point of Authentication
Configure access for all accounts through as few centralized points of authentication as
possible, including network, security, and cloud systems.

## 6.2.3 Ensure root PATH Integrity

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The root user can execute any command on the system and could be fooled into executing
programs unintentionally if the PATH is not set correctly.

#### Rationale:
Including the current working directory (.) or other writable directory in root 's executable
path makes it likely that an attacker can gain superuser access by forcing an administrator
operating as root to execute a Trojan horse program.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>for x in $(echo $PATH | tr ":" " ") ; do
    if [ -d "$x" ] ; then
    ls -ldH "$x" | awk '
$9 == "." {print "PATH contains current working directory (.)"}
$3 != "root" {print $9, "is not owned by root"}
substr($1,6,1) != "-" {print $9, "is group writable"}
substr($1,9,1) != "-" {print $9, "is world writable"}'
    else
        echo "$x is not a directory"
    fi
done</code></pre>

#### Remediation:
Correct or justify any items discovered in the Audit step.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.

## 6.2.4 Ensure no legacy “+” entries exist in /etc/master.passwd

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The character '+' in various files used to be markers for systems to insert data from NIS
maps at a certain point in a system configuration file. These entries are no longer required
on most systems, but may exist in files that have been imported from other platforms.

#### Rationale:
These entries may provide an avenue for attackers to gain privileged access on the system.

#### Audit:
Run the following command and verify that no output is returned:
<pre><code># grep '^\+:' /etc/master.passwd</code></pre>

#### Remediation:
Remove any legacy '+' entries from <code>/etc/master.passwd</code> if they exist.

#### CIS Controls:
Version 7
16.2 Configure Centralized Point of Authentication
Configure access for all accounts through as few centralized points of authentication as
possible, including network, security, and cloud systems.

## 6.2.5 Ensure no legacy “+” entries exist in /etc/group

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
The character '+' in various files used to be markers for systems to insert data from NIS
maps at a certain point in a system configuration file. These entries are no longer required
on most systems, but may exist in files that have been imported from other platforms.

#### Rationale:
These entries may provide an avenue for attackers to gain privileged access on the system.

#### Audit:
Run the following command and verify that no output is returned:
<pre><code># grep '^\+:' /etc/group</code></pre>

#### Remediation:
Remove any legacy '+' entries from <code>/etc/group</code> if they exist.

#### CIS Controls:
Version 7
16.2 Configure Centralized Point of Authentication
Configure access for all accounts through as few centralized points of authentication as
possible, including network, security, and cloud systems.

## 6.2.6 Ensure root is the only UID 0 account

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Any account with UID <code>0</code> has superuser privileges on the system.

#### Rationale:
This access must be limited to only the default <code>root</code> account and only from the system
console. Administrative access must be through an unprivileged account using an approved
mechanism as noted in Item 5.6 Ensure access to the su command is restricted.

#### Audit:
Run the following command and verify that only "root" is returned:
<pre><code># awk -F: '($3 == 0) { print $1 }' /etc/passwd
root</code></pre>

#### Remediation:
Remove any users other than <code>root</code> with UID <code>0</code> or assign them a new UID if appropriate.

#### CIS Controls:
Version 7
5.1 Establish Secure Configurations
Maintain documented, standard security configuration standards for all authorized
operating systems and software.






## 6.2.13 Ensure no users have .rhosts files

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
While no <code>.rhosts</code> files are shipped by default, users can easily create them.

#### Rationale:
This action is only meaningful if <code>.rhosts</code> support is permitted in the file <code>/etc/pam.conf</code> .
Even though the <code>.rhosts</code> files are ineffective if support is disabled in <code>/etc/pam.conf</code> , they
may have been brought over from other systems and could contain information useful to
an attacker for those other systems.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>#!/bin/sh
grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
"'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
    if [ ! -d "$dir" ]; then
        echo "The home directory ($dir) of user $user does not exist."
    else
        for file in $dir/.rhosts; do
            if [ ! -h "$file" -a -f "$file" ]; then
                echo ".rhosts file in $dir"
            fi
        done
     fi
done</code></pre>

#### Remediation:
Making global modifications to users' files without alerting the user community can result
in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring
policy be established to report user <code>.rhosts</code> files and determine the action to be taken in
accordance with site policy.

#### CIS Controls:
Version 7

16.4 Encrypt or Hash all Authentication Credentials

Encrypt or hash with a salt all authentication credentials when stored.

## 6.2.14 Ensure all groups in /etc/passwd exist in /etc/group

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Over time, system administration errors and changes can lead to groups being defined in
<code>/etc/passwd</code> but not in <code>/etc/group</code>.

#### Rationale:
Groups defined in the <code>/etc/passwd</code> file but not in the <code>/etc/group</code> file pose a threat to
system security since group permissions are not properly managed.

#### Audit:
Run the following commands and verify no results are returned:
<pre><code># grep -v '^[:space:]*#' /etc/passwd | cut -s -d: -f4 | sort -nu > file1
# grep -v '^[:space:]*#' /etc/group | cut -s -d: -f3 | sort -nu > file2
# comm -23 file1 file2
</code></pre>

#### Remediation:
Analyze the output of the Audit step above and perform the appropriate action to correct
any discrepancies found.

#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control


## 6.2.15 Ensure no duplicate UIDs exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Although the useradd program will not let you create a duplicate User ID (UID), it is
possible for an administrator to manually edit the <code>/etc/passwd</code> file and change the UID
field.

#### Rationale:
Users must be assigned unique UIDs for accountability and to ensure appropriate access
protections.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>#!/bin/sh
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
    [ -z "$x" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
        echo "Duplicate UID ($2): $users"
    fi
done</code></pre>

#### Remediation:
Based on the results of the audit script, establish unique UIDs and review all files owned by
the shared UIDs to determine which UID they are supposed to belong to.

#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control

## 6.2.16 Ensure no duplicate GIDs exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Although the groupadd program will not let you create a duplicate Group ID (GID), it is
possible for an administrator to manually edit the <code>/etc/group</code> file and change the GID field.

#### Rationale:
User groups must be assigned unique GIDs for accountability and to ensure appropriate
access protections.

#### Audit:
Run the following script and verify no results are returned:

<pre><code>#!/bin/sh
cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
    echo "Duplicate GID ($x) in /etc/group"
done</code></pre>

#### Remediation:
Based on the results of the audit script, establish unique GIDs and review all files owned by
the shared GID to determine which group they are supposed to belong to.


#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control

## 6.2.17 Ensure no duplicate user names exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Although the adduser program will not let you create a duplicate user name, it is possible
for an administrator to manually edit the <code>/etc/passwd</code> file and change the user name.

#### Rationale:
If a user is assigned a duplicate user name, it will create and have access to files with the
first UID for that username in <code>/etc/passwd</code> . For example, if "test4" has a UID of 1000 and a
subsequent "test4" entry has a UID of 2000, logging in as "test4" will use UID 1000.
Effectively, the UID is shared, which is a security problem.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>#!/bin/sh
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x ; do 
    echo "Duplicate login name ${x} in /etc/passwd"
done</code></pre>

#### Remediation:
Based on the results of the audit script, establish unique user names for the users. File
ownerships will automatically reflect the change as long as the users have unique UIDs.

#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control

## 6.2.18 Ensure no duplicate group names exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Although the pw program will not let you create a duplicate group name, it is
possible for an administrator to manually edit the <code>/etc/group</code> file and change the group
name.

#### Rationale:
If a group is assigned a duplicate group name, it will create and have access to files with the
first GID for that group in <code>/etc/group</code> . Effectively, the GID is shared, which is a security
problem.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>#!/bin/sh
cut -d: -f1 /etc/group | sort | uniq -d | while read x ; do 
    echo "Duplicate group name ${x} in /etc/group"
done</code></pre>

#### Remediation:
Based on the results of the audit script, establish unique names for the user groups. File
group ownerships will automatically reflect the change as long as the groups have unique
GIDs.

#### CIS Controls:
Version 7

16 Account Monitoring and Control

Account Monitoring and Control

## 6.2.19 Ensure all users' home directories exist

#### Profile Applicability:
* Level 1 - Server
* Level 1 - Workstation

#### Description:
Users can be defined in /etc/passwd without a home directory or with a home directory
that does not actually exist.

#### Rationale:
If the user's home directory does not exist or is unassigned, the user will be placed in "/"
and will not be able to write any files or have local environment variables set.

#### Audit:
Run the following script and verify no results are returned:
<pre><code>#!/bin/sh
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do
    if [ ! -d "$dir" ]; then
        echo "The home directory ($dir) of user $user does not exist."
    fi
done</code></pre>

#### Remediation:
If any users' home directories do not exist, create them and make sure the respective user
owns the directory. Users without an assigned home directory should be removed or
assigned a home directory as appropriate.

#### Notes:
The audit script checks all users with interactive shells except halt, sync, shutdown, and
nfsnobody.

#### CIS Controls:
Version 7

5.1 Establish Secure Configurations

Maintain documented, standard security configuration standards for all authorized
operating systems and software.
