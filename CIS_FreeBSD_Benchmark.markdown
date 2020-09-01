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
