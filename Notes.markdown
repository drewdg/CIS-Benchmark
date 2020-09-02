Bolded need reviewing
Italics have already been confirmed by Ed.

## Services: (X)


## Network Configuration: (X)

*Ensure secure ICMP redirects are not accepted - NA for FreeBSD* 

*Ensure bogus ICMP responses are ignored - NA for FreeBSD*

*Ensure Reverse Path Filtering is enabled - NA for freebsd*

*Ensure DCCP is disabled - NA for FreeBSD*



## Auditing and Logging.

(4.1.1.3)  Ensure auditing for processes that start prior to auditd is enabled - Not possible in FreeBSD

(4.1.1.3)  Ensure audit_backlog_limit is sufficient - Not possible in FreeBSD

(4.1.3) Ensure changes to system administration scope (sudoers) is collected - Is this possible on FreeBSD?

(4.1.5) Ensure session initiation information is collected - Not necessary of FreeBSD due to the 'lo' parameter already logging this.

(4.1.6) Ensure events that modify date and time information are collected - Not possible in FreeBSD

(4.1.7) Ensure events that modify the system's Mandatory Access Controls are collected - Not possible in FreeBSD

**4.1.7 Ensure events that modify user/group information are collected - Is this the 'aa' class in audit_config?**

(4.1.12) Ensure successful file system mounts are collected - Not possible in FreeBSD

(4.1.13) Ensure use of privileged commands is collected - Not possible in FreeBSD

(4.1.15) Ensure kernel module loading and unloading is collected - Not possible in FreeBSD

(4.1.17) Ensure the audit configuration is immutable - Not possible on FreeBSD

4.2.2 Configure Journald - Systemd-journald looks to be Linux only so I skipped this section


## Cron/Perodic: (X)

Finished

## SSH (X)

*5.2.20 Ensure system-wide crypto policy is not over-ridden - N/A for FreeBSD*

## User Accounts & Environment

(5.5.1.2) Ensure minimum days between password changes is 7 or more - No option for this in FreeBSD

5.5.1.2 - No option to switch warning for individual users

Ensure inactive password lock is 30 days or less - No option on FreeBSD

Ensure all users last password change date is in the past - No option on FreeBSD

Ensure system accounts are secured - No(?) direct translation to FreeBSD

## PAM and Password Settings

(5.2.2)Ensure lockout for failed password attempts is configured - NA for FreeBSD

(5.2.3)Ensure password reuse is limited - NA for FreeBSD

## FileSystem

**6.1.5 Check if the find command is doable (personal note)**

## User and Group Settings 

(6.2.19) Ensure shadow group is empty - NA for FreeBSD

6.2.14 Ensure all groups in /etc/passwd exist in /etc/group - Script relies on Grep -P this is not an option of FreeBSd which breaks the script, can this be fixed?
