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

