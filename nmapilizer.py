#!/usr/bin/env python3
"""
NMAPILIZER v7.1.0 — Nmap XML Visualiser & Analyser
====================================================
Import one or many Nmap XML files (-oX), merge/dedupe hosts, analyse every
host/port, flag weak / outdated / dangerous services, look for known exploits
(local Exploit-DB lookups + a built-in offline exploit/CVE database +
CVEs parsed from NSE `vulners`/`vuln` script output), score risk, and produce:

  * MODE A — CLI report bundle (default)
      DDMMYYYY_XXX_Nmapilizer_Report/
          index.html        executive 1-page dashboard
          hosts.html        every host, risk-ranked
          host_<ip>.html    one deep-dive page per host
          ports.html        every open port (searchable/sortable)
          findings.html     every flag, severity-sorted, for manual review
          exploits.html     every exploit/CVE match with references
          assets/style.css  assets/app.js
          data.json  hosts.csv  ports.csv  findings.csv  exploits.csv
          summary.txt

  * MODE B — Live web dashboard  (--serve)
      One responsive page in the browser. Drag & drop / import XML files
      right in the page, results re-render instantly (no reload, no lag),
      live search/filter/sort, host detail drawer, optional --watch <dir>
      auto-refresh when scan files change on disk.

v7: startup PRECHECK (searchsploit, Metasploit, local vulnerability DB) + CPE-based matching against a local
SQLite DB built from NVD / CISA KEV / EPSS / Exploit-DB / Metasploit — run `--update-db` once.
Stdlib only. Python 3.9+. No pip installs. Never scans anything itself —
it only analyses Nmap output you supply (passive analysis).
Author: @BudSec  (github.com/buddysecurity · facebook.com/budsec · linkedin.com/company/buddysecurity · youtube.com/@budsec · instagram.com/thebudsec)
Licence: use on systems/networks you own or are
authorised to assess only.
"""
from __future__ import annotations
import argparse, csv, hashlib, html, io, json, os, re, shutil, subprocess
import sys, threading, time, webbrowser
import sqlite3, gzip, platform, socket, glob, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET

VERSION = "7.1.0"
AUTHOR_NAME = "@BudSec"
AUTHOR_LINKS = [
    ("Facebook",  "https://www.facebook.com/budsec"),
    ("LinkedIn",  "https://www.linkedin.com/company/buddysecurity/"),
    ("YouTube",   "https://youtube.com/@budsec"),
    ("Instagram", "https://www.instagram.com/thebudsec"),
    ("GitHub",    "https://github.com/buddysecurity"),
]
_SOC_SVG = {
    "GitHub":    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.15-1.11-1.46-1.11-1.46-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2z"/></svg>',
    "Facebook":  '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M14 8h3V4h-3a4 4 0 0 0-4 4v2H7v4h3v8h4v-8h3l1-4h-4V8.5c0-.3.2-.5.5-.5z"/></svg>',
    "LinkedIn":  '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="9" width="4" height="12"/><circle cx="5" cy="5" r="2.2"/><path d="M10 9h3.8v1.8c.6-1.1 2-2.1 4-2.1 3.5 0 4.2 2.3 4.2 5.3V21h-4v-6c0-1.4 0-3-1.9-3s-2.1 1.4-2.1 2.9V21h-4z"/></svg>',
    "YouTube":   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M22 8.2a3 3 0 0 0-2.1-2.1C18 5.6 12 5.6 12 5.6s-6 0-7.9.5A3 3 0 0 0 2 8.2 31 31 0 0 0 1.6 12c0 1.3.1 2.6.4 3.8a3 3 0 0 0 2.1 2.1c1.9.5 7.9.5 7.9.5s6 0 7.9-.5a3 3 0 0 0 2.1-2.1c.3-1.2.4-2.5.4-3.8s-.1-2.6-.4-3.8z"/><path class="cut" d="M10 15V9l5 3z"/></svg>',
    "Instagram": '<svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="18" height="18" rx="5" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="17.4" cy="6.6" r="1.2"/></svg>',
}
def author_buttons():
    """Labelled, clickable social buttons for report headers."""
    return '<div class="socbtns">' + "".join(
        f'<a class="socbtn" href="{u}" target="_blank" rel="noopener noreferrer">{_SOC_SVG[n]}<span>{n}</span></a>'
        for n, u in AUTHOR_LINKS) + f'<span class="socby">by <b>{AUTHOR_NAME}</b></span></div>'

THEME_VAR_KEYS = ("bg", "panel", "panel2", "line", "txt", "mut", "acc", "hover", "codebg", "codefg",
                  "onacc", "shadow", "crit", "high", "med", "low", "info", "danger")
_SAFE_CSS_VAL = re.compile(r"^[#0-9a-zA-Z(),.%\s-]{1,140}$")
def theme_css_from_vars(vars_, scheme="dark"):
    """CSS :root block built from the dashboard's CURRENT theme values (sanitised)."""
    parts = []
    for k in THEME_VAR_KEYS:
        v = str((vars_ or {}).get(k, "")).strip()
        if v and _SAFE_CSS_VAL.match(v): parts.append(f"--{k}:{v}")
    if not parts: return ""
    parts.append("color-scheme:" + ("light" if scheme == "light" else "dark"))
    return "\n/* exported in the dashboard's current theme */\n:root{" + ";".join(parts) + "}\n"

def author_html(compact=False):
    """Author name + social links (inline SVG, no external assets)."""
    links = "".join(f'<a class="soc" href="{u}" target="_blank" rel="noopener noreferrer" title="{n}" aria-label="{n}">{_SOC_SVG[n]}</a>'
                    for n, u in AUTHOR_LINKS)
    if compact:
        return f'<span class="authorline"><b>{AUTHOR_NAME}</b>{links}</span>'
    return (f'<div class="authorcard"><div class="authortxt"><span class="mut small">Created by</span>'
            f'<b class="shimmer">{AUTHOR_NAME}</b></div><div class="socrow">{links}</div></div>')
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_CVES_PER_SERVICE = 25

class Progress:
    """What the tool is doing right now — polled by the dashboard (/api/progress) and drawn as a CLI bar."""
    def __init__(self):
        self.lock = threading.Lock(); self.cli = False
        self.s = {"active": False, "phase": "", "detail": "", "pct": 0.0, "job": 0}
        self._last = 0.0
    def start(self, phase, detail=""):
        with self.lock:
            self.s = {"active": True, "phase": phase, "detail": detail, "pct": 0.0, "job": self.s["job"] + 1}
    def update(self, pct=None, phase=None, detail=None, force=False):
        now = time.time()
        if not force and now - self._last < 0.08: return
        self._last = now
        with self.lock:
            if pct is not None: self.s["pct"] = max(0.0, min(1.0, pct))
            if phase is not None: self.s["phase"] = phase
            if detail is not None: self.s["detail"] = detail
            self.s["active"] = True; snap = dict(self.s)
        if self.cli: _bar("Progress", int(snap["pct"] * 1000), 1000, f"{snap['phase']} {snap['detail']}".strip())
    def done(self):
        with self.lock: self.s["active"] = False; self.s["pct"] = 1.0
        if self.cli: _bar_end()
    def snapshot(self):
        with self.lock: return dict(self.s)
PROG = Progress()

SEV_VAR = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low", "Info": "info"}
SEV_WEIGHT = {"Critical": 35, "High": 20, "Medium": 10, "Low": 4, "Info": 1}
SEV_COLOR = {"Critical": "#e5484d", "High": "#f76b15", "Medium": "#ffb224",
             "Low": "#46a758", "Info": "#6e7f96"}

def esc(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)

def parse_version(s: str):
    """'2.4.49' / '7.80' / '1.0.1f' -> (2,4,49) etc. Returns tuple or None."""
    if not s:
        return None
    m = re.search(r"(\d+(?:\.\d+){0,3})", str(s))
    if not m:
        return None
    try:
        return tuple(int(p) for p in m.group(1).split("."))
    except Exception:
        return None

def vlt(a, b) -> bool:
    """version tuple a < b, padding with zeros."""
    if a is None or b is None:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))

def slug_ip(ip: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", ip).strip("_")

# --------------------------------------------------------------------------
# KNOWLEDGE BASE 1 — dangerous / sensitive ports
# port -> (service_label, severity, why, remediation)
# --------------------------------------------------------------------------
DANGEROUS_PORTS = {
    21:   ("FTP", "High", "Cleartext file transfer; credentials and data cross the wire in plain text. Anonymous login is common.", "Disable FTP. Use SFTP/FTPS. If FTP must stay, disallow anonymous login and restrict by source IP."),
    23:   ("Telnet", "Critical", "Cleartext remote shell — credentials are trivially sniffed. A classic initial-access vector.", "Disable Telnet immediately. Use SSH (port 22) with key authentication."),
    69:   ("TFTP", "High", "Unauthenticated UDP file transfer; often used to exfiltrate configs or serve malware.", "Disable TFTP unless required for PXE/config boot, then restrict to a management VLAN."),
    111:  ("RPCbind / Portmapper", "Medium", "Enumerates RPC services and has a history of amplification/reflection abuse.", "Restrict with firewall rules; disable if NFS/RPC is not required."),
    135:  ("MS-RPC", "Medium", "Windows RPC endpoint mapper; frequent enumeration and lateral-movement target.", "Do not expose beyond trusted LAN segments; firewall at the perimeter."),
    137:  ("NetBIOS-NS", "Medium", "Legacy name service; enables enumeration and name-spoofing/poisoning.", "Disable NetBIOS over TCP/IP where possible."),
    139:  ("NetBIOS / SMB (legacy)", "High", "Legacy SMB transport tied to SMBv1-era attacks (EternalBlue class).", "Disable SMBv1 and NetBIOS; use SMB 445 with signing required."),
    161:  ("SNMP (UDP)", "Medium", "SNMP v1/v2c uses cleartext community strings (often 'public'/'private') and leaks full device config.", "Use SNMPv3 (authPriv), change default communities, restrict to NMS hosts."),
    389:  ("LDAP (cleartext)", "Medium", "Directory binds and queries in cleartext unless StartTLS is enforced.", "Require LDAPS (636) or StartTLS with signed binds."),
    445:  ("SMB", "High", "Prime ransomware / lateral-movement target. Risk is critical if SMBv1 is enabled or signing is not required.", "Patch, disable SMBv1, require SMB signing, restrict to hosts that need file sharing."),
    512:  ("rexec", "Critical", "Legacy cleartext remote execution service.", "Disable; use SSH."),
    513:  ("rlogin", "Critical", "Legacy cleartext login trusting .rhosts — trivially abused.", "Disable; use SSH."),
    514:  ("rsh / syslog", "High", "rsh is cleartext remote shell; unauthenticated syslog accepts forged logs.", "Disable rsh; restrict syslog ingestion to known senders."),
    873:  ("rsync (daemon)", "High", "rsync daemon modules are frequently left unauthenticated and readable/writable.", "Require auth + hosts allow, or tunnel over SSH."),
    1080: ("SOCKS proxy", "High", "An open proxy can be abused as a pivot / anonymiser by third parties.", "Require authentication and bind to internal interfaces only."),
    1433: ("Microsoft SQL Server", "High", "Database listener; brute-force and xp_cmdshell abuse lead straight to data/host compromise.", "Never expose to untrusted networks; enforce strong auth and patch level."),
    1521: ("Oracle DB", "High", "Database listener with a long history of default accounts and listener attacks.", "Restrict to application servers; apply Oracle CPU patches."),
    2049: ("NFS", "High", "Exports are often world-readable; mis-scoped exports leak or allow writing files.", "Export only to specific hosts, use NFSv4 with Kerberos where possible."),
    2375: ("Docker API (cleartext)", "Critical", "Unauthenticated Docker API = remote root on the host. Actively exploited for cryptomining.", "Never expose 2375. Use 2376 with mutual TLS, or the local socket only."),
    2376: ("Docker API (TLS)", "Medium", "Docker API over TLS — still full host control if client certs are weak/leaked.", "Verify mutual TLS, rotate client certs, restrict source IPs."),
    3306: ("MySQL / MariaDB", "High", "Database listener frequently targeted by brute force and ransomware ('PLEASE_READ_ME' campaigns).", "Bind to localhost/app tier only, strong root password, TLS for remote access."),
    3389: ("RDP", "High", "Most-brute-forced remote access service; BlueKeep-class RCE history.", "Put behind VPN/ZTNA, enable NLA, MFA, lockout policy; never internet-expose directly."),
    5432: ("PostgreSQL", "High", "Database listener; weak pg_hba rules are a common breach root cause.", "Restrict pg_hba to app hosts, require SCRAM + TLS."),
    5900: ("VNC", "High", "Remote desktop with historically weak (8-char, DES) authentication and cleartext sessions.", "Tunnel over SSH/VPN, set a strong password, or replace with a modern gateway."),
    6379: ("Redis", "Critical", "Redis ships with no authentication by default; exposed instances are routinely fully compromised.", "Set requirepass, bind to localhost/private nets, enable protected mode, firewall it."),
    8009: ("AJP (Tomcat)", "High", "AJP connector was the Ghostcat (CVE-2020-1938) vector — file read / possible RCE.", "Disable AJP if unused, or bind it to localhost with a secret."),
    8080: ("HTTP (alternate)", "Low", "Alternate HTTP often hosts forgotten admin panels, test apps or proxies with weaker hardening than the main site.", "Inventory what this is; apply the same hardening/auth as the primary web service."),
    8443: ("HTTPS (alternate)", "Low", "Alternate HTTPS often hosts admin consoles (Tomcat/iLO/DRAC etc.).", "Inventory and restrict admin consoles to management networks."),
    9200: ("Elasticsearch", "Critical", "Elasticsearch historically shipped without auth; exposed clusters have caused mass data breaches.", "Enable security (auth+TLS), bind to private network, snapshot before remediation."),
    9300: ("Elasticsearch (transport)", "High", "Cluster transport port; exposure allows joining/attacking the cluster.", "Bind to private cluster network only."),
    11211:("Memcached", "High", "Unauthenticated cache; UDP amplification (memcrash) and data leakage.", "Bind to localhost, disable UDP, firewall; enable SASL if remote access is needed."),
    27017:("MongoDB", "Critical", "MongoDB instances have been ransomed en masse when exposed without auth.", "Enable authentication, bind to private interfaces, TLS on."),
    27018:("MongoDB (shardsvr)", "High", "MongoDB shard port — same exposure risk as 27017.", "Private network only, auth enabled."),
    4786: ("Cisco Smart Install", "Critical", "Smart Install client (CVE-2018-0171) allows unauthenticated config replacement / RCE on Cisco switches.", "Disable with 'no vstack' unless actively provisioning."),
    5060: ("SIP", "Medium", "VoIP signalling; toll fraud and extension enumeration target.", "Restrict to carrier SBC IPs, enable digest auth + rate limiting."),
    27015:("Steam / game server query", "Low", "Game/query services have seen reflection/amplification abuse.", "Rate-limit and firewall if not intentionally public."),
    53:   ("DNS", "Low", "An open resolver can be abused for DNS amplification; zone transfer (AXFR) leaks your whole zone.", "Disable open recursion for outsiders; restrict AXFR to secondaries — check NSE dns-zone-transfer output."),
    25:   ("SMTP", "Low", "Mail relay — check it's not an open relay and that STARTTLS is offered.", "Disable open relaying, require auth for submission, offer STARTTLS."),
    110:  ("POP3 (cleartext)", "Medium", "Cleartext mailbox credentials.", "Require POP3S (995) or disable in favour of IMAPS."),
    143:  ("IMAP (cleartext)", "Medium", "Cleartext mailbox credentials and mail.", "Require IMAPS (993) / StartTLS."),
    993:  ("IMAPS", "Info", "Encrypted IMAP — expected; verify certificate validity in findings.", "Keep TLS current."),
    995:  ("POP3S", "Info", "Encrypted POP3 — expected; verify certificate validity in findings.", "Keep TLS current."),
}

CLEARTEXT_SERVICES = {  # service name fragment -> severity
    "ftp": "High", "telnet": "Critical", "http": "Low", "pop3": "Medium",
    "imap": "Medium", "smtp": "Low", "ldap": "Medium", "vnc": "High",
    "redis": "Critical", "mongodb": "Critical",
}

# --------------------------------------------------------------------------
# KNOWLEDGE BASE 2 — outdated / end-of-life version rules
# (product_regex, threshold_version, severity, cve_or_ref, title, advice)
# A finding fires when parsed version < threshold.
# --------------------------------------------------------------------------
OUTDATED_RULES = [
    (r"apache httpd", (2,4,58), "High", "multiple CVEs (e.g. CVE-2023-43622, CVE-2024-27316)",
     "Apache httpd is outdated", "Upgrade to the latest 2.4.x. Older 2.4 builds carry request-smuggling, SSRF and DoS fixes you are missing. Apache 2.2.x is fully end-of-life."),
    (r"apache httpd", (2,3,0), "Critical", "EOL branch",
     "Apache httpd 2.2 or older — END OF LIFE", "2.2 went EOL in 2017 and receives no fixes. Migrate to 2.4.x immediately."),
    (r"openssh", (8,9), "Medium", "CVE-2024-6387 (regreSSHion) affects 8.5p1–9.7p1; older builds miss many fixes",
     "OpenSSH is old", "Upgrade OpenSSH. Check specifically for regreSSHion (8.5p1–9.7p1 on glibc Linux = Critical, unauthenticated RCE as root)."),
    (r"openssl", (1,0,2), "Critical", "CVE-2014-0160 (Heartbleed) class",
     "OpenSSL 1.0.1/older era — Heartbleed generation", "This OpenSSL generation is the Heartbleed era and long EOL. Upgrade to 1.1.1 (also EOL Sep 2023) or preferably 3.x, and rotate keys/certs."),
    (r"openssl", (3,0,0), "Medium", "1.1.1 EOL 2023-09-11",
     "OpenSSL 1.1.1 or older — end of life", "OpenSSL 1.1.1 support ended 11 Sep 2023. Move to 3.0 LTS / 3.2+."),
    (r"microsoft-iis", (8,0), "High", "IIS 7.x/8.0 on WS2008R2/2012 — EOL OS",
     "Very old Microsoft IIS", "IIS ≤8.0 implies Windows Server 2012 or older (extended support ended Oct 2023). Plan an OS migration."),
    (r"microsoft-iis", (10,0), "Low", "pre-10 IIS",
     "Microsoft IIS older than 10.0", "Consider moving to IIS 10 on a supported Windows Server release."),
    (r"nginx", (1,18,0), "Medium", "multiple CVEs",
     "nginx is old", "Upgrade nginx to a current stable/mainline release; several resolver/HTTP2 issues affect old builds."),
    (r"vsftpd", (3,0,0), "High", "vsftpd 2.3.4 = backdoor CVE-2011-2523",
     "vsftpd older than 3.0 — CHECK FOR 2.3.4 BACKDOOR", "If the banner is exactly vsftpd 2.3.4, treat as CRITICAL: that tarball contained a backdoor opening a shell on 6200/tcp. Upgrade to 3.0.5."),
    (r"proftpd", (1,3,7), "Medium", "multiple CVEs",
     "ProFTPD is outdated", "Upgrade ProFTPD to the latest 1.3.8.x; older builds have mod_copy and TLS issues."),
    (r"samba smbd|samba", (4,13,0), "High", "multiple CVEs (fruit/Baron Samedit class)",
     "Samba is outdated", "Upgrade Samba. Old versions carry pre-auth RCE/file-read issues; also confirm SMBv1 is disabled."),
    (r"mysql", (5,8), "Medium", "MySQL 5.7 EOL Oct 2023",
     "MySQL 5.7 or older — end of life", "MySQL 5.7 reached EOL in Oct 2023. Plan migration to 8.0/8.4 LTS."),
    (r"mariadb", (10,5), "Medium", "old MariaDB branch",
     "MariaDB is on an old branch", "Move to a supported MariaDB LTS branch (10.11 / 11.4)."),
    (r"postgresql", (13,0), "Medium", "PG ≤12 EOL",
     "PostgreSQL 12 or older — end of life", "PostgreSQL 12 support ended Nov 2024 (11 in 2023, 10 in 2022). Upgrade to 15/16."),
    (r"php", (7,4), "High", "PHP ≤7.3 EOL",
     "PHP 7.3 or older — end of life", "PHP branches live ~3 years. Anything ≤7.3 is unpatched. Move to 8.2/8.3."),
    (r"php", (8,1), "Medium", "PHP 7.4/8.0 EOL",
     "PHP 7.4 / 8.0 — end of life", "7.4 EOL Nov 2022, 8.0 EOL Nov 2023. Move to 8.2+."),
    (r"tomcat|apache-coyote", (9,0), "Medium", "Tomcat 7/8.5 EOL",
     "Apache Tomcat is on an EOL branch", "Tomcat 7 EOL 2021, 8.5 EOL Mar 2024. Move to 9/10.1 and disable AJP if unused."),
    (r"exim", (4,94), "High", "multiple RCE CVEs (21Nails etc.)",
     "Exim is outdated", "Upgrade Exim — old builds have a long run of pre-auth RCEs (e.g. 21Nails, CVE-2023-42115)."),
    (r"microsoft.*exchange|exchange", (15,1), "High", "ProxyLogon/ProxyShell generation",
     "Old Microsoft Exchange — ProxyLogon/ProxyShell era check needed", "Verify the exact CU/SU level manually. Pre-Mar-2021 CUs were mass-exploited (ProxyLogon)."),
    (r"wordpress", (6,0), "Low", "core/plugin CVE stream",
     "WordPress older than 6.x", "Update WordPress core, themes and plugins; most WP compromises are outdated plugins, not core."),
    (r"openssh", (7,4), "High", "multiple CVEs",
     "OpenSSH 7.4 or older", "This generation misses years of fixes including CVE-2018-15473 (user enumeration). Upgrade."),
    (r"dropbear", (2020,0), "Medium", "old Dropbear",
     "Dropbear SSH is old", "Update Dropbear (common on embedded/IoT) to a current release and rotate host keys if very old."),
    (r"lighttpd", (1,4,55), "Low", "old lighttpd",
     "lighttpd is outdated", "Upgrade lighttpd to a current 1.4.x release."),
    (r"bind|named", (9,12), "Medium", "BIND CVE stream",
     "ISC BIND is old", "Upgrade BIND; DNS servers get frequent high-severity DoS/RCE fixes."),
    (r"dovecot", (2,3,0), "Medium", "old Dovecot",
     "Dovecot is outdated", "Upgrade Dovecot to a current 2.3.x release."),
    (r"postfix", (3,5), "Low", "old Postfix",
     "Postfix is on an old release", "Move to a supported Postfix 3.7+ stream."),
]

# --------------------------------------------------------------------------
# KNOWLEDGE BASE 3 — built-in offline exploit / CVE database
# (keyword_regex_on_product_or_service, title, severity, cve, exploit_ref, msf_module)
# --------------------------------------------------------------------------
EXPLOIT_DB = [
    (r"vsftpd 2\.3\.4", "vsftpd 2.3.4 Backdoor — unauthenticated root shell (6200/tcp)", "Critical", "CVE-2011-2523", "Exploit-DB 17491", "exploit/unix/ftp/vsftpd_234_backdoor"),
    (r"apache httpd 2\.4\.49", "Apache 2.4.49 Path Traversal / RCE", "Critical", "CVE-2021-41773 / CVE-2021-42013", "Exploit-DB 50383", "exploit/linux/http/apache_normalize_path_rce"),
    (r"apache httpd 2\.4\.5[0-2]", "Apache 2.4.50-52 issues (SSRF / traversal follow-ups)", "High", "CVE-2021-42013, CVE-2022-22720", "Exploit-DB search: apache 2.4.50", ""),
    (r"samba.*3\.|smbd 3\.", "Samba 3.x/4.x pre-4.6.4 — SambaCry unauthenticated RCE (is_known_pipename)", "Critical", "CVE-2017-7494", "Exploit-DB 42060", "exploit/linux/samba/is_known_pipename"),
    (r"microsoft-ds|netbios-ssn|samba", "SMB — check for EternalBlue (MS17-010) if SMBv1 / unpatched Windows", "Critical", "CVE-2017-0144 (MS17-010)", "Exploit-DB 42031 (scanner)", "auxiliary/scanner/smb/smb_ms17_010"),
    (r"microsoft.*terminal|ms-wbt|rdp", "RDP — BlueKeep unauthenticated RCE on unpatched Win7/2008", "Critical", "CVE-2019-0708", "Exploit-DB 47158 (scanner)", "auxiliary/scanner/rdp/cve_2019_0708_bluekeep_rce"),
    (r"openssh 8\.[5-9]|openssh 9\.[0-7]", "OpenSSH regreSSHion — possible unauthenticated RCE (glibc Linux, 8.5p1–9.7p1)", "Critical", "CVE-2024-6387", "Exploit-DB search: regreSSHion", ""),
    (r"openssl 1\.0\.1", "OpenSSL Heartbleed — private key / memory disclosure", "Critical", "CVE-2014-0160", "Exploit-DB 32764", "auxiliary/scanner/ssl/openssl_heartbleed"),
    (r"elasticsearch", "Elasticsearch — check Groovy RCE (old) / unauthenticated data access", "High", "CVE-2014-3120, CVE-2015-1427", "Exploit-DB 33370", "exploit/multi/elasticsearch/script_mvel_rce"),
    (r"apache.*tomcat|apache-coyote", "Tomcat — Ghostcat AJP file read (8009) / manager weak creds", "High", "CVE-2020-1938", "Exploit-DB 48143", "auxiliary/admin/http/tomcat_ghostcat"),
    (r"jenkins", "Jenkins — check unauthenticated script console / CVE-2024-23897 CLI file read", "High", "CVE-2024-23897", "Exploit-DB search: jenkins", "exploit/multi/http/jenkins_script_console"),
    (r"weblogic", "Oracle WebLogic — multiple unauthenticated RCEs (T3/IIOP/HTTP)", "Critical", "CVE-2020-14882, CVE-2019-2725", "Exploit-DB search: weblogic", "exploit/multi/http/oracle_weblogic_wls_rce"),
    (r"exchange|microsoft.*httpapi.*exchange", "Exchange — ProxyLogon / ProxyShell SSRF+RCE chains", "Critical", "CVE-2021-26855, CVE-2021-34473", "Exploit-DB search: proxylogon", "exploit/windows/http/exchange_proxylogon_rce"),
    (r"fortigate|fortios", "FortiOS SSL-VPN — path traversal credential leak / RCE", "Critical", "CVE-2018-13379, CVE-2022-40684", "Exploit-DB 47287", ""),
    (r"citrix|netscaler", "Citrix ADC/Gateway — Citrix Bleed / unauthenticated RCE", "Critical", "CVE-2019-19781, CVE-2023-4966", "Exploit-DB 47936", ""),
    (r"confluence", "Atlassian Confluence — unauthenticated OGNL RCE", "Critical", "CVE-2022-26134, CVE-2021-26084", "Exploit-DB search: confluence ognl", "exploit/multi/http/atlassian_confluence_unauth_rce"),
    (r"log4j|java.*log4", "Log4Shell — if a Java service logs attacker input with log4j 2.0–2.14.1", "Critical", "CVE-2021-44228", "— (verify manually with canary)", "auxiliary/scanner/http/log4shell_scanner"),
    (r"spring", "Spring Framework — Spring4Shell (JDK9+, WAR deployment)", "Critical", "CVE-2022-22965", "Exploit-DB search: spring4shell", ""),
    (r"docker", "Docker API exposed — unauthenticated container escape to host root", "Critical", "— (misconfiguration)", "Manual: curl http://host:2375/version", ""),
    (r"redis", "Redis unauthenticated — CONFIG SET dir/dbfilename write, replica RCE", "Critical", "— (misconfiguration) + CVE-2022-0543 (Debian Lua sandbox escape)", "Exploit-DB 51853", "exploit/linux/redis/redis_unauth_exec"),
    (r"mongodb|mongo", "MongoDB unauthenticated access — full DB read/write/ransom", "High", "— (misconfiguration)", "Manual review", ""),
    (r"memcached", "Memcached UDP amplification / unauthenticated data access", "High", "CVE-2018-1000115", "—", ""),
    (r"proftpd 1\.3\.5", "ProFTPD 1.3.5 mod_copy unauthenticated file copy", "High", "CVE-2015-3306", "Exploit-DB 36742", "exploit/unix/ftp/proftpd_modcopy_exec"),
    (r"exim 4\.8|exim 4\.9[0-2]", "Exim — Qualys 21Nails / CVE-2019-10149 RCE generation", "Critical", "CVE-2019-10149, CVE-2020-28007+", "Exploit-DB search: exim", ""),
    (r"wordpress", "WordPress — plugin/theme CVEs dominate; enumerate with WPScan", "Medium", "various", "Tool: wpscan", ""),
    (r"drupal", "Drupal — Drupalgeddon2 unauthenticated RCE (core <7.58/8.5.1)", "Critical", "CVE-2018-7600", "Exploit-DB 44449", "exploit/unix/webapp/drupal_drupalgeddon2"),
    (r"joomla", "Joomla — check core version; multiple unauthenticated RCE history", "High", "CVE-2023-23752 etc.", "Exploit-DB search: joomla", ""),
    (r"phpmyadmin", "phpMyAdmin exposed — auth bypass / RCE history; should never be public", "High", "CVE-2018-12613 etc.", "Exploit-DB search: phpmyadmin", ""),
    (r"vnc", "VNC weak/no authentication — full desktop control", "High", "— (misconfiguration)", "Manual review", ""),
    (r"snmp", "SNMP default communities (public/private) — full device recon/config", "Medium", "— (misconfiguration)", "Tool: onesixtyone / snmpwalk", "auxiliary/scanner/snmp/snmp_login"),
    (r"smart install", "Cisco Smart Install — unauthenticated remote code/config (4786)", "Critical", "CVE-2018-0171", "Exploit-DB 44122", ""),
    (r"git", ".git exposure on web root — full source/credential disclosure", "High", "— (misconfiguration)", "Tool: git-dumper", ""),
]

WEAK_SCRIPT_HINTS = [
    # (script id fragment, substring in output (lower), severity, title)
    ("ssl-heartbleed", "vulnerable", "Critical", "Heartbleed VULNERABLE (per NSE ssl-heartbleed)"),
    ("smb-vuln-ms17-010", "vulnerable", "Critical", "EternalBlue MS17-010 VULNERABLE (per NSE)"),
    ("smb-vuln", "vulnerable", "High", "SMB vulnerability reported by NSE smb-vuln-*"),
    ("vulners", "cve-", "Info", "NSE vulners reports CVE(s) for this service — see exploits page"),
    ("http-vuln", "vulnerable", "High", "HTTP vulnerability reported by NSE http-vuln-*"),
    ("ftp-anon", "allowed", "High", "Anonymous FTP login allowed (per NSE ftp-anon)"),
    ("ftp-vsftpd-backdoor", "vulnerable", "Critical", "vsftpd backdoor reported by NSE"),
    ("smtp-open-relay", "open relay", "High", "SMTP open relay (per NSE smtp-open-relay)"),
    ("dns-zone-transfer", "axfr", "Medium", "DNS zone transfer appears possible (per NSE)"),
    ("ssl-cert", "expired", "Medium", "TLS certificate issue (expired — per NSE ssl-cert output)"),
    ("smb-security-mode", "signing disabled", "Medium", "SMB signing disabled / not required"),
    ("rdp-vuln-ms12-020", "vulnerable", "High", "RDP MS12-020 vulnerability reported by NSE"),
    ("mysql-empty-password", "empty", "Critical", "MySQL root/empty password reported by NSE"),
    ("mongodb-info", "", "Info", "MongoDB info disclosed by NSE — verify authentication is required"),
    ("redis-info", "", "Info", "Redis info disclosed by NSE — verify requirepass is set"),
]

# v2: user custom highlight keywords [(keyword, severity), ...] — filled by CLI/custom rules
HIGHLIGHTS = []

# --------------------------------------------------------------------------
# DATA MODEL
# --------------------------------------------------------------------------
@dataclass
class Port:
    protocol: str = "tcp"
    portid: int = 0
    state: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    method: str = ""
    conf: str = ""
    cpes: list = field(default_factory=list)
    scripts: dict = field(default_factory=dict)   # id -> output
    @property
    def banner(self) -> str:
        return " ".join(x for x in [self.product, self.version, self.extrainfo] if x).strip()
    @property
    def full_service(self) -> str:
        return (self.product or self.service or "").strip()

@dataclass
class Host:
    ip: str = ""
    ipv6: str = ""
    mac: str = ""
    vendor: str = ""
    hostnames: list = field(default_factory=list)
    status: str = "up"
    os_name: str = ""
    os_accuracy: str = ""
    os_cpes: list = field(default_factory=list)
    ports: dict = field(default_factory=dict)     # (proto,portid) -> Port
    scripts: dict = field(default_factory=dict)   # host scripts id -> output
    uptime: str = ""
    distance: str = ""
    sources: list = field(default_factory=list)   # source xml filenames
    first_seen_scan: str = ""
    risk_score: int = 0
    risk_level: str = "Info"
    @property
    def display_name(self) -> str:
        return self.hostnames[0] if self.hostnames else self.ip
    @property
    def open_ports(self):
        return [p for p in sorted(self.ports.values(), key=lambda x: (x.protocol, x.portid))
                if p.state.startswith("open")]

@dataclass
class Finding:
    host: str = ""
    hostname: str = ""
    port: int = 0
    protocol: str = ""
    service: str = ""
    banner: str = ""
    severity: str = "Info"
    category: str = ""      # Dangerous Port / Outdated / Exploit / Weak Config / NSE / Exposure
    title: str = ""
    detail: str = ""
    remediation: str = ""
    cve: str = ""
    reference: str = ""
    priority: str = ""      # v7: P1 KEV · P2 public exploit · P3 EPSS/CVSS high · P4 other
    confidence: str = ""    # v7: CPE match / Banner guess / NSE script / Built-in rule

@dataclass
class ExploitRef:
    host: str = ""
    port: int = 0
    service: str = ""
    title: str = ""
    severity: str = "Info"
    cve: str = ""
    source: str = ""        # Built-in DB / searchsploit / NSE vulners
    reference: str = ""     # EDB id / msf module / url-ish text
    detail: str = ""
    priority: str = ""
    confidence: str = ""

# --------------------------------------------------------------------------
# PARSER — Nmap XML (-oX)
# --------------------------------------------------------------------------
def parse_nmap_xml_text(text: str, source_name: str = "<memory>"):
    """Parse one XML document (string) -> (hosts list, scan_meta dict)."""
    hosts, meta = [], {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"{source_name}: not valid XML / not an Nmap file ({e})")
    if root.tag != "nmaprun":
        raise ValueError(f"{source_name}: root element is <{root.tag}>, expected <nmaprun> (use nmap -oX)")
    meta = {"scanner": root.get("scanner", "nmap"), "args": root.get("args", ""),
            "start": root.get("startstr", ""), "version": root.get("version", ""),
            "source": source_name}
    for h_el in root.findall("host"):
        h = Host()
        st = h_el.find("status")
        h.status = st.get("state", "up") if st is not None else "up"
        for a in h_el.findall("address"):
            t, addr = a.get("addrtype", ""), a.get("addr", "")
            if t == "ipv4" and not h.ip: h.ip = addr
            elif t == "ipv6" and not h.ipv6: h.ipv6 = addr
            elif t == "mac": h.mac, h.vendor = addr, a.get("vendor", "")
        if not h.ip and h.ipv6: h.ip = h.ipv6
        hn_el = h_el.find("hostnames")
        if hn_el is not None:
            for hn in hn_el.findall("hostname"):
                if hn.get("name"): h.hostnames.append(hn.get("name"))
        # OS
        os_el = h_el.find("os")
        if os_el is not None:
            best = None
            for m in os_el.findall("osmatch"):
                if best is None or int(m.get("accuracy", 0)) > int(best.get("accuracy", 0)):
                    best = m
            if best is not None:
                h.os_name, h.os_accuracy = best.get("name", ""), best.get("accuracy", "")
                for c in best.findall(".//cpe"):
                    if c.text: h.os_cpes.append(c.text)
        ports_el = h_el.find("ports")
        if ports_el is not None:
            for p_el in ports_el.findall("port"):
                p = Port(protocol=p_el.get("protocol", "tcp"),
                         portid=int(p_el.get("portid", 0)))
                st_el = p_el.find("state")
                p.state = st_el.get("state", "") if st_el is not None else ""
                sv = p_el.find("service")
                if sv is not None:
                    p.service = sv.get("name", ""); p.product = sv.get("product", "")
                    p.version = sv.get("version", ""); p.extrainfo = sv.get("extrainfo", "")
                    p.tunnel = sv.get("tunnel", ""); p.method = sv.get("method", "")
                    p.conf = sv.get("conf", "")
                    for c in sv.findall("cpe"):
                        if c.text: p.cpes.append(c.text)
                for s in p_el.findall("script"):
                    p.scripts[s.get("id", "")] = s.get("output", "")
                h.ports[(p.protocol, p.portid)] = p
        hs_el = h_el.find("hostscript")
        if hs_el is not None:
            for s in hs_el.findall("script"):
                h.scripts[s.get("id", "")] = s.get("output", "")
        up = h_el.find("uptime")
        if up is not None: h.uptime = up.get("seconds", "")
        dist = h_el.find("distance")
        if dist is not None: h.distance = dist.get("value", "")
        h.sources.append(source_name)
        h.first_seen_scan = meta.get("start", "")
        if h.ip:
            hosts.append(h)
    return hosts, meta

def parse_nmap_xml_file(path: Path):
    return parse_nmap_xml_text(path.read_text(encoding="utf-8", errors="replace"), path.name)

# --------------------------------------------------------------------------
# v2 — .nmap (normal) and .gnmap (grepable) parsers + format sniffing
# --------------------------------------------------------------------------
def split_banner(banner: str):
    """'Apache httpd 2.4.49 ((Unix) OpenSSL/1.0.1f)' -> (product, version, extrainfo).
    'OpenSSH 8.9p1 Ubuntu 3ubuntu0.1' -> ('OpenSSH', '8.9p1', 'Ubuntu 3ubuntu0.1')."""
    banner = (banner or "").strip()
    if not banner:
        return "", "", ""
    m = re.search(r"\b(\d+(?:\.\d+){0,3}[a-z]?\d*(?:p\d+)?)\b", banner)
    if not m:
        return banner, "", ""
    product = banner[:m.start()].strip(" -")
    version = m.group(1)
    extra = banner[m.end():].strip()
    return product, version, extra

def parse_gnmap_text(text: str, source_name: str = "<memory>"):
    hosts, meta = [], {"scanner": "nmap (gnmap)", "args": "", "start": "", "version": "", "source": source_name}
    by_ip = {}
    for line in text.splitlines():
        if line.startswith("#") and "scan initiated" in line:
            meta["start"] = line.split("scan initiated", 1)[1].strip().split(" as:")[0].strip()
            if " as: " in line: meta["args"] = line.split(" as: ", 1)[1].strip()
            continue
        if not line.startswith("Host: "):
            continue
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)\s*(.*)$", line)
        if not m:
            continue
        ip, hostname, rest = m.group(1), m.group(2), m.group(3)
        h = by_ip.get(ip)
        if h is None:
            h = Host(ip=ip); by_ip[ip] = h; hosts.append(h)
        if hostname and hostname not in h.hostnames: h.hostnames.append(hostname)
        if source_name not in h.sources: h.sources.append(source_name)
        if rest.startswith("Status:"):
            h.status = "up" if "up" in rest.lower() else "down"
        elif rest.startswith("Ports:"):
            h.status = "up"
            ports_part = rest[len("Ports:"):].split("\t")[0]
            ports_part = re.sub(r",?\s*Ignored State:.*$", "", ports_part)
            for entry in ports_part.split(","):
                entry = entry.strip()
                if not entry: continue
                f = entry.split("/")
                # port/state/proto/owner/service/rpc/version/...
                if len(f) < 3: continue
                try: portid = int(f[0])
                except ValueError: continue
                p = Port(protocol=f[2] or "tcp", portid=portid, state=f[1])
                p.service = f[4] if len(f) > 4 else ""
                ver_field = f[6] if len(f) > 6 else ""
                if ver_field:
                    p.product, p.version, p.extrainfo = split_banner(ver_field)
                    if not p.product: p.product = p.service
                h.ports[(p.protocol, p.portid)] = p
        elif rest.startswith("OS:"):
            h.os_name = rest[len("OS:"):].split("\t")[0].strip()
    return hosts, meta

def parse_nmap_text(text: str, source_name: str = "<memory>"):
    hosts, meta = [], {"scanner": "nmap (.nmap)", "args": "", "start": "", "version": "", "source": source_name}
    for line in text.splitlines():
        if line.startswith("# Nmap") and " scan " in line:
            meta["start"] = line.strip()
    blocks = re.split(r"(?m)^Nmap scan report for ", text)
    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines: continue
        head = lines[0].strip()
        h = Host()
        m = re.match(r"^(.*?)\s*\((\d[\d.]+|[0-9a-fA-F:]+)\)\s*$", head)
        if m:
            name, h.ip = m.group(1).strip(), m.group(2)
            if name and name != h.ip: h.hostnames.append(name)
        else:
            h.ip = head.split()[0] if head.split() else ""
        if not h.ip: continue
        h.sources.append(source_name)
        cur_port, cur_script = None, None
        for line in lines[1:]:
            ls = line.strip()
            if ls.startswith("Host is up"): h.status = "up"
            elif "Host seems down" in ls or ls.startswith("Note: Host seems down"): h.status = "down"
            mac = re.match(r"MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?", ls)
            if mac: h.mac, h.vendor = mac.group(1), mac.group(2) or ""
            pm = re.match(r"^(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", ls)
            if pm and not ls.startswith("PORT"):
                banner = (pm.group(5) or "").strip()
                product, version, extra = split_banner(banner) if banner else ("", "", "")
                cur_port = Port(protocol=pm.group(2), portid=int(pm.group(1)), state=pm.group(3),
                                service=pm.group(4), product=product, version=version, extrainfo=extra)
                h.ports[(cur_port.protocol, cur_port.portid)] = cur_port
                cur_script = None
                continue
            if ls.startswith("OS details:"): h.os_name = ls.split(":", 1)[1].strip()
            elif ls.startswith("Running:") and not h.os_name: h.os_name = ls.split(":", 1)[1].strip()
            elif ls.startswith("Aggressive OS guesses:") and not h.os_name: h.os_name = ls.split(":", 1)[1].split("(")[0].strip()
            elif ls.startswith("Service Info:"):
                cm = re.search(r"CPE:\s*(cpe:\S+)", ls)
                if cm: h.os_cpes.append(cm.group(1))
                om = re.search(r"OS:\s*([^;]+)", ls)
                if om and not h.os_name: h.os_name = om.group(1).strip()
            if ls.startswith("|"):
                sm = re.match(r"^\|_?\s*([\w][\w\-]*):(?:\s+(.*)|\s*)$", ls)
                if sm:
                    cur_script = sm.group(1)
                    target = cur_port.scripts if cur_port is not None else h.scripts
                    target[cur_script] = sm.group(2) or ""
                elif cur_script:
                    cont = re.sub(r"^\|\s*", "", ls)
                    target = cur_port.scripts if cur_port is not None else h.scripts
                    target[cur_script] = target.get(cur_script, "") + "\n" + cont
        hosts.append(h)
    return hosts, meta

def sniff_format(text: str, filename: str = "") -> str:
    ext = Path(filename).suffix.lower()
    head = text[:4000]
    if "<nmaprun" in head or ext == ".xml": return "xml"
    if ext == ".gnmap" or re.search(r"(?m)^Host:\s+\S+\s+\([^)]*\)\s+(Ports:|Status:)", head): return "gnmap"
    if ext == ".nmap" or "Nmap scan report for" in head: return "nmap"
    if "<" in head[:50]: return "xml"
    return "nmap"

def parse_any_text(text: str, source_name: str = "<memory>"):
    fmt = sniff_format(text, source_name)
    if fmt == "xml": return parse_nmap_xml_text(text, source_name)
    if fmt == "gnmap": return parse_gnmap_text(text, source_name)
    hosts, meta = parse_nmap_text(text, source_name)
    if not hosts:
        raise ValueError(f"{source_name}: no hosts found — is this an Nmap .nmap/.gnmap/.xml output file?")
    return hosts, meta

def parse_any_file(path: Path):
    return parse_any_text(path.read_text(encoding="utf-8", errors="replace"), path.name)

def merge_hosts(all_hosts, incoming, source_name):
    """Merge incoming hosts into dict ip->Host (union of ports, freshest wins per port)."""
    for h in incoming:
        if h.ip not in all_hosts:
            all_hosts[h.ip] = h
        else:
            cur = all_hosts[h.ip]
            for name in h.hostnames:
                if name not in cur.hostnames: cur.hostnames.append(name)
            for k, p in h.ports.items(): cur.ports[k] = p
            cur.scripts.update(h.scripts)
            if h.os_name and (not cur.os_name or (h.os_accuracy or "0") >= (cur.os_accuracy or "0")):
                cur.os_name, cur.os_accuracy = h.os_name, h.os_accuracy
            if source_name not in cur.sources: cur.sources.append(source_name)
            if h.mac and not cur.mac: cur.mac = h.mac
    return all_hosts

def collect_input_files(inputs):
    files = []
    for item in inputs or []:
        p = Path(item)
        if p.is_dir():
            for ext in ("*.xml", "*.nmap", "*.gnmap"):
                files += sorted(p.rglob(ext))
        elif any(ch in item for ch in "*?["):
            files += sorted(Path().glob(item))
        elif p.is_file():
            files.append(p)
        else:
            print(f"[!] Input not found, skipped: {item}", file=sys.stderr)
    # de-dupe, keep order
    seen, out = set(), []
    for f in files:
        if str(f) not in seen: seen.add(str(f)); out.append(f)
    return out

# --------------------------------------------------------------------------
# SEARCHSPLOIT (optional, auto-detected)
# --------------------------------------------------------------------------
class Searchsploit:
    def __init__(self, binary=None):
        self.binary = binary or shutil.which("searchsploit")
        self.cache = {}
        self.available = bool(self.binary)
    def lookup(self, term: str, limit=5):
        term = (term or "").strip()
        if not self.available or len(term) < 3:
            return []
        key = term.lower()
        if key in self.cache: return self.cache[key]
        results = []
        try:
            proc = subprocess.run([self.binary, "--json", term],
                                  capture_output=True, text=True, timeout=10)
            data = json.loads(proc.stdout or "{}")
            for row in (data.get("RESULTS_EXPLOIT") or [])[:limit]:
                results.append({
                    "title": row.get("Title", ""), "edb": str(row.get("EDB-ID", "")),
                    "date": row.get("Date", ""), "type": row.get("Type", ""),
                    "platform": row.get("Platform", ""), "path": row.get("Path", "")})
        except Exception:
            pass
        self.cache[key] = results
        return results

# --------------------------------------------------------------------------
# ANALYSER
# --------------------------------------------------------------------------
def analyse(hosts: dict, searchsploit: Searchsploit, use_searchsploit=True,
            verbose=False):
    """Returns (findings, exploits). Mutates hosts with risk_score/level."""
    findings, exploits = [], []
    EXPOSURE_ONLY = ("Dangerous / Sensitive Port", "Cleartext / Unencrypted Service")
    def add_f(h, p, sev, cat, title, detail, rem="", cve="", ref=""):
        if cat in EXPOSURE_ONLY and sev != "Info":      # an open port / exposed service alone is informational
            detail = (f"{detail} Typical risk if reachable from untrusted networks: {sev}. Reported as Informational — "
                      f"severity is raised only when a CVE or exploit actually matches this service.")
            sev = "Info"
        findings.append(Finding(
            host=h.ip, hostname=h.display_name,
            port=p.portid if p else 0, protocol=p.protocol if p else "",
            service=(p.full_service or p.service) if p else "",
            banner=p.banner if p else "", severity=sev, category=cat,
            title=title, detail=detail, remediation=rem, cve=cve, reference=ref))
    def add_x(h, p, title, sev, cve, source, ref, detail=""):
        key = (h.ip, p.portid if p else 0, title)
        if any((e.host, e.port, e.title) == key for e in exploits): return
        exploits.append(ExploitRef(host=h.ip, port=p.portid if p else 0,
            service=(p.full_service or p.service) if p else "", title=title,
            severity=sev, cve=cve, source=source, reference=ref, detail=detail))

    _order = sorted(hosts, key=lambda x: tuple(int(o) for o in x.split(".") if o.isdigit()) if x.replace(".", "").isdigit() else (999,))
    PROG.start("Analysing hosts", f"0/{len(_order)}")
    for _hi, ip in enumerate(_order, 1):
        PROG.update(0.02 + 0.50 * _hi / max(1, len(_order)), "Analysing hosts", f"host {_hi}/{len(_order)} · {ip}")
        h = hosts[ip]
        for p in h.open_ports:
            label = f"{p.protocol}/{p.portid}"
            blob = f"{p.product} {p.version} {p.service} {p.extrainfo}".strip()
            # 1) dangerous ports
            if p.portid in DANGEROUS_PORTS:
                name, sev, why, rem = DANGEROUS_PORTS[p.portid]
                # plain HTTP on 80 is Low, not in dict; 8080 already Low etc.
                add_f(h, p, sev, "Dangerous / Sensitive Port",
                      f"{name} exposed on {label}",
                      f"{why} Service identified as: {blob or p.service or 'unknown'}.",
                      rem)
            # 2) cleartext protocol by service name (if not already covered by port)
            svc_low = (p.service or "").lower()
            if p.tunnel != "ssl" and p.portid not in DANGEROUS_PORTS:
                for frag, sev in CLEARTEXT_SERVICES.items():
                    if frag == svc_low or svc_low.startswith(frag):
                        add_f(h, p, sev, "Cleartext / Unencrypted Service",
                              f"Cleartext service '{p.service}' on {label}",
                              f"'{p.service}' runs without TLS on this port. Credentials/data may be observable on the network path.",
                              "Move to the encrypted variant (HTTPS/SSH/LDAPS/IMAPS…) or tunnel/restrict this service.")
                        break
            # 3) outdated / EOL versions
            vt = parse_version(p.version) or parse_version(p.extrainfo)
            hay = blob.lower()
            for rx, thresh, sev, cve, title, advice in OUTDATED_RULES:
                if re.search(rx, hay):
                    if vt and vlt(vt, thresh):
                        add_f(h, p, sev, "Outdated / End-of-Life Software", title,
                              f"Detected: {blob}. This is older than {'.'.join(map(str, thresh))}. {advice}",
                              advice, cve=cve)
                    break  # first matching product rule only (most specific first)
            # special: vsftpd 2.3.4 exact
            if re.search(r"vsftpd\s+2\.3\.4", hay):
                add_f(h, p, "Critical", "Outdated / End-of-Life Software",
                      "vsftpd 2.3.4 BACKDOOR build detected",
                      "Banner is exactly vsftpd 2.3.4 — the compromised tarball with a built-in root shell backdoor (port 6200/tcp). Treat this host as compromised until proven otherwise.",
                      "Remove immediately, rebuild from a trusted source, investigate for compromise.", cve="CVE-2011-2523")
            # special: regreSSHion range
            if re.search(r"openssh", hay) and vt and (8,5) <= vt[:2] and vt < (9,8):
                add_f(h, p, "Critical", "Outdated / End-of-Life Software",
                      "OpenSSH in regreSSHion range (8.5p1–9.7p1)",
                      f"Detected OpenSSH {p.version}. On glibc-based Linux this range is vulnerable to CVE-2024-6387, an unauthenticated race-condition RCE as root. Verify OS/libc, patch priority is urgent if Linux+glibc.",
                      "Upgrade to OpenSSH 9.8p1+ (or vendor-patched build).", cve="CVE-2024-6387")
            # special: SMBv1 hint from extrainfo/scripts
            smb_blob = " ".join(p.scripts.values()).lower()
            if p.portid in (139, 445) and ("smbv1" in smb_blob or "smb 1" in smb_blob or "protocol: smb 1" in smb_blob):
                pass  # covered by NSE hint rules below; avoid double-firing without evidence
            # 4) built-in exploit DB
            for rx, title, sev, cve, edb, msf in EXPLOIT_DB:
                if re.search(rx, hay, re.I):
                    ref = edb + (f" · Metasploit: {msf}" if msf else "")
                    add_x(h, p, title, sev, cve, "Built-in DB", ref,
                          f"Matched banner: {blob}")
                    name_only = not re.search(r"\d", rx)     # no version in the rule => just "this service is present"
                    if sev in ("Critical", "High"):
                        add_f(h, p, "Info" if name_only else sev, "Known Exploit Available", title,
                              (f"Matched on the service name only ({blob}) — there is no version evidence, so this is reported as Informational. "
                               f"The exploit lead is listed on the Exploits page; confirm the exact version/patch level before treating it as vulnerable. Typical impact if vulnerable: {sev}."
                               if name_only else
                               f"A known exploit/technique matches this exact service/banner ({blob}). Verify patch level manually — a banner match is a strong lead, not proof of exploitability."),
                              "Confirm exact build/patch level, apply the vendor fix, and re-scan. See the Exploits page for references.",
                              cve=cve, ref=ref)
            # 5) searchsploit
            if use_searchsploit and searchsploit.available and p.product:
                term = f"{p.product} {p.version}".strip()
                for r in searchsploit.lookup(term):
                    add_x(h, p, r["title"], "High", "", "Exploit-DB (local)",
                          f"Exploit-DB {r['edb']} ({r['type']}/{r['platform']}, {r['date']})",
                          f"local Exploit-DB lookup '{term}' → {r['path']}")
            # 6) NSE script hints + CVE extraction
            for sid, out in p.scripts.items():
                low = (out or "").lower()
                for frag, needle, sev, title in WEAK_SCRIPT_HINTS:
                    if frag in sid and (not needle or needle in low):
                        add_f(h, p, sev, "NSE Script Evidence", title,
                              f"NSE script '{sid}' output: {out[:600]}",
                              "Review the script output in the host detail page and remediate per vendor guidance.")
                if sid == "vulners" or "vulners" in sid:
                    for cve in sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", out or ""))):
                        add_x(h, p, f"{cve} reported by NSE vulners for {blob or p.service}",
                              "High", cve, "NSE vulners",
                              f"https://nvd.nist.gov/vuln/detail/{cve}",
                              (out or "")[:400])
                for cve in sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", out or ""))):
                    if "vulnerable" in low and sid not in ("vulners",):
                        add_x(h, p, f"{cve} mentioned in NSE '{sid}' (state: vulnerable)",
                              "High", cve, f"NSE {sid}", "", (out or "")[:400])
            # 6b) v2 custom highlights — user-supplied keywords (--highlight / custom rules)
            for kw, hsev in HIGHLIGHTS:
                if kw.lower() in blob.lower() or kw.lower() in " ".join(p.scripts.values()).lower():
                    add_f(h, p, hsev, "Custom Highlight",
                          f"Custom keyword '{kw}' matched on {label}",
                          f"Your custom highlight keyword '{kw}' appears in this service/banner or its script output: {blob}. Flagged for your manual review per your own rule.",
                          "Review this match — you defined this keyword in --highlight or your custom-rules file.")
            # 7) generic exposures
            if not p.product and not p.version and p.service in ("", "unknown"):
                add_f(h, p, "Info", "Exposure", f"Unidentified service on {label}",
                      "Nmap could not identify this service (try -sV --version-all). An unknown listening service should still be inventoried and owned.",
                      "Identify the owner/purpose; close it if it is not required.")
        # host-level: no open ports / down
        if h.status != "up":
            add_f(h, None, "Info", "Exposure", "Host reported down / no response in scan",
                  "This host was not 'up' in the scan data. It may be filtered, off, or blocking probes.", "")
        # risk score
        score = 0
        for f in findings:
            if f.host == ip: score += SEV_WEIGHT[f.severity]
        h.risk_score = min(100, score)
        h.risk_level = ("Critical" if h.risk_score >= 70 else "High" if h.risk_score >= 40
                        else "Medium" if h.risk_score >= 20 else "Low" if h.risk_score > 0 else "Clean")
    if INTEL is not None:
        enrich_with_intel(hosts, findings, exploits, INTEL, searchsploit if use_searchsploit else None, MAX_CVES_PER_SERVICE)
    # every open port ends up in Findings: with no CVE/exploit/NSE evidence it is Informational
    PROG.update(0.97, "Finalising", "listing open ports", force=True)
    covered = {(f.host, f.port) for f in findings}
    for h in hosts.values():
        for p in h.open_ports:
            if (h.ip, p.portid) in covered: continue
            svc = (p.full_service or p.service or "unknown service").strip()
            findings.append(Finding(host=h.ip, hostname=h.display_name, port=p.portid, protocol=p.protocol, service=svc,
                banner=p.banner, severity="Info", category="Exposure",
                title=f"Open port {p.protocol}/{p.portid} — {svc}",
                detail="Port is open and reachable. No known CVE, exploit or script evidence matched this service, so it is informational only.",
                remediation="Confirm the service is meant to be reachable; close or firewall it if not."))
    findings.sort(key=lambda f: (SEV_RANK[f.severity], f.priority or "P9", f.host, f.port))
    exploits.sort(key=lambda e: (SEV_RANK[e.severity], e.priority or "P9", e.host, e.port))
    PROG.done()
    return findings, exploits

# --------------------------------------------------------------------------
# v4 — EXPLOITATION GUIDES knowledge base + CVE aggregation
# Guides are VALIDATION / lab-reproduction guidance for authorised testing:
# confirm the version, verify with a scanner/check, reproduce only in a lab
# or in-scope environment, record evidence, remediate.
# --------------------------------------------------------------------------
CVSS_KNOWN = {  # widely published base scores; UI labels them "verify on NVD"
    "CVE-2021-44228": 10.0, "CVE-2021-26855": 9.8, "CVE-2021-34473": 9.8,
    "CVE-2022-26134": 9.8, "CVE-2018-7600": 9.8, "CVE-2020-1938": 9.8,
    "CVE-2018-0171": 9.8, "CVE-2019-0708": 9.8, "CVE-2021-42013": 9.8,
    "CVE-2024-6387": 8.1, "CVE-2017-7494": 7.5, "CVE-2014-0160": 7.5,
    "CVE-2021-41773": 7.5, "CVE-2011-2523": 7.6, "CVE-2020-14882": 9.8,
    "CVE-2019-19781": 9.8, "CVE-2023-4966": 7.5, "CVE-2019-10149": 9.8,
    "CVE-2015-3306": 9.8, "CVE-2017-0144": 8.8, "CVE-2022-22965": 9.8,
    "CVE-2018-13379": 9.8, "CVE-2024-23897": 9.8, "CVE-2020-28007": 9.8,
}
GUIDES = [
    {"id": "vsftpd-backdoor", "cves": ["CVE-2011-2523"], "patterns": [r"vsftpd 2\.3\.4"],
     "title": "vsftpd 2.3.4 Backdoor — unauthenticated root shell", "severity": "Critical",
     "summary": "The vsftpd 2.3.4 tarball distributed in 2011 contained a backdoor: a username containing ':)' triggers a shell listener on tcp/6200. A banner match should be treated as suspected compromise, not just a vuln.",
     "tools": ["nmap (vsftpd-backdoor NSE script)", "netcat", "searchsploit"],
     "steps": ["Confirm the banner is exactly 'vsftpd 2.3.4' with a version scan.",
               "Run the dedicated NSE check against the host (validation only).",
               "In an authorised lab, connect to tcp/6200 after triggering to confirm the shell listener exists; do NOT do this on third-party systems.",
               "If confirmed: isolate the host, preserve evidence, rebuild from trusted media — patching alone is not enough for a backdoor."],
     "commands": [{"label": "NSE backdoor check", "cmd": "nmap -sV --script ftp-vsftpd-backdoor -p 21 {HOST}"},
                  {"label": "Look up the public exploit", "cmd": "searchsploit vsftpd 2.3.4"},
                  {"label": "Check for the backdoor listener (lab only)", "cmd": "nmap -p 6200 {HOST}"}],
     "remediation": "Remove this build entirely, rebuild the service from a trusted source, rotate all credentials, and investigate the host for compromise."},
    {"id": "apache-41773", "cves": ["CVE-2021-41773", "CVE-2021-42013"], "patterns": [r"apache httpd 2\.4\.49", r"apache httpd 2\.4\.50"],
     "title": "Apache 2.4.49/2.4.50 Path Traversal → RCE", "severity": "Critical",
     "summary": "A path normalisation flaw in Apache 2.4.49 (and the incomplete 2.4.50 fix) lets unauthenticated attackers traverse outside the web root; with CGI enabled it becomes remote code execution as the web-server user.",
     "tools": ["curl", "nmap http-vuln NSE scripts", "searchsploit"],
     "steps": ["Confirm exact version 2.4.49 or 2.4.50 from the banner.",
               "Validate traversal with a harmless read of a known file (e.g. /etc/passwd) using the encoded path — in scope/lab only.",
               "Check whether CGI (mod_cgi) is enabled; traversal + CGI = RCE, traversal alone = file disclosure.",
               "Record the response evidence, then prioritise the upgrade — this CVE was mass-exploited within days of disclosure."],
     "commands": [{"label": "Traversal validation (harmless file read)", "cmd": "curl -s http://{HOST}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd | head"},
                  {"label": "NSE vulnerability scan", "cmd": "nmap -sV --script http-vuln-cve2021-41773 -p {PORT} {HOST}"},
                  {"label": "Public exploit reference", "cmd": "searchsploit apache 2.4.49"}],
     "remediation": "Upgrade Apache to 2.4.51+ (preferably latest 2.4.x). Disable CGI where not required."},
    {"id": "sambacry", "cves": ["CVE-2017-7494"], "patterns": [r"samba.*3\.|smbd 3\.|samba 4\.[0-5]"],
     "title": "SambaCry — Samba pre-4.6.4 unauthenticated RCE", "severity": "Critical",
     "summary": "Samba 3.5–4.6.3 allows an authenticated-or-anonymous (writable share) attacker to upload a shared library and have smbd execute it as root via the is_known_pipename flaw.",
     "tools": ["nmap smb NSE scripts", "smbclient", "searchsploit", "Metasploit (lab)"],
     "steps": ["Confirm Samba version < 4.6.4 and enumerate shares/permissions.",
               "Identify a writable share — the exploit needs one to plant the library.",
               "Validate in a lab clone with the public module; on production, treat version + writable share as sufficient evidence.",
               "Check for artefacts (unexpected .so files in share paths) if exploitation is suspected."],
     "commands": [{"label": "Enumerate shares", "cmd": "smbclient -L //{HOST} -N"},
                  {"label": "SMB vuln checks", "cmd": "nmap -sV --script smb-vuln* -p 445 {HOST}"},
                  {"label": "Public exploit reference", "cmd": "searchsploit samba 3.5"}],
     "remediation": "Upgrade Samba to 4.6.4+, remove anonymous/writable shares, restrict 445 to hosts that need it."},
    {"id": "eternalblue", "cves": ["CVE-2017-0144", "CVE-2017-0143", "CVE-2017-0145"], "patterns": [r"ms17-010|eternalblue"],
     "title": "EternalBlue — MS17-010 SMBv1 RCE", "severity": "Critical",
     "summary": "A flaw in SMBv1 handling allows unauthenticated remote code execution as SYSTEM on unpatched Windows (and was weaponised by WannaCry/NotPetya). The reliable validator is the NSE smb-vuln-ms17-010 script state.",
     "tools": ["nmap (smb-vuln-ms17-010)", "Metasploit auxiliary scanner (lab)"],
     "steps": ["Run the NSE check — a 'VULNERABLE' state is definitive validation without exploiting.",
               "Confirm SMBv1 is enabled (it is required for this issue).",
               "Do not run the weaponised exploit on production; the scanner result is your evidence.",
               "Prioritise patching/isolation — hosts with this are one step from wormable compromise."],
     "commands": [{"label": "Definitive NSE validation", "cmd": "nmap -sV --script smb-vuln-ms17-010 -p 445 {HOST}"},
                  {"label": "Check SMBv1 status", "cmd": "nmap --script smb-protocols -p 445 {HOST}"}],
     "remediation": "Apply MS17-010, disable SMBv1 everywhere, and segment SMB traffic."},
    {"id": "bluekeep", "cves": ["CVE-2019-0708"], "patterns": [r"bluekeep|rdp.*vuln|ms-wbt"],
     "title": "BlueKeep — pre-auth RDP RCE (Win7/2008)", "severity": "Critical",
     "summary": "A use-after-free in RDP allows unauthenticated code execution before login on Windows 7 / Server 2008 (and XP/2003). Any internet-facing RDP of that era must be assumed exposed.",
     "tools": ["nmap (rdp NSE scripts)", "searchsploit"],
     "steps": ["Confirm the OS generation (Win7/2008) and that 3389 is reachable.",
               "Run the RDP NSE checks to gather evidence (the rdp-vuln-ms12-020 state and protocol info).",
               "Validate exploitability only in a lab clone — the public exploit can crash the target (BSOD).",
               "Check whether NLA is enabled; NLA reduces (does not remove) the risk."],
     "commands": [{"label": "RDP NSE checks", "cmd": "nmap -sV --script rdp-vuln-ms12-020,rdp-enum-encryption -p 3389 {HOST}"},
                  {"label": "Public references", "cmd": "searchsploit bluekeep"}],
     "remediation": "Patch (May 2019 update), enable NLA, put RDP behind a VPN/gateway, and plan migration off EOL Windows."},
    {"id": "regreshion", "cves": ["CVE-2024-6387"], "patterns": [r"openssh 8\.[5-9]|openssh 9\.[0-7]|regreSSHion"],
     "title": "regreSSHion — OpenSSH unauthenticated RCE (glibc Linux)", "severity": "Critical",
     "summary": "A signal-handler race in sshd (8.5p1–9.7p1 on glibc Linux) regresses the 2006 CVE-2006-5051 and can yield unauthenticated root code execution after many attempts. Banner range + Linux/glibc is the trigger to verify the distro package level.",
     "tools": ["nmap version scan", "vendor advisories (distro package check)"],
     "steps": ["Confirm the OpenSSH version is inside 8.5p1–9.7p1.",
               "Confirm the host is glibc-based Linux (the flaw is glibc-specific) and check the distro's patched package version — many distros backported the fix without changing the banner.",
               "There is no safe public 'one-shot' validator; version + OS + package changelog is the accepted evidence.",
               "If unpatched: restrict 22/tcp by source IP immediately as a compensating control."],
     "commands": [{"label": "Confirm banner precisely", "cmd": "nmap -sV -p 22 --script ssh-hostkey,ssh2-enum-algos {HOST}"},
                  {"label": "On the host itself: check package changelog", "cmd": "zgrep -i CVE-2024-6387 /usr/share/doc/openssh-server/changelog* 2>/dev/null | head"}],
     "remediation": "Upgrade to OpenSSH 9.8p1+ or the distro-patched build; restrict SSH by source IP meanwhile."},
    {"id": "heartbleed", "cves": ["CVE-2014-0160"], "patterns": [r"heartbleed|openssl 1\.0\.1"],
     "title": "Heartbleed — OpenSSL memory disclosure", "severity": "Critical",
     "summary": "The TLS heartbeat extension in OpenSSL 1.0.1–1.0.1f leaks up to 64KB of server memory per request — including private keys and session data. The NSE ssl-heartbleed script is a safe, definitive validator.",
     "tools": ["nmap (ssl-heartbleed)", "openssl s_client"],
     "steps": ["Run the NSE script — 'VULNERABLE' is definitive and non-destructive.",
               "Identify every TLS service on the host using the vulnerable library (not just 443).",
               "Assume private keys are compromised if the service was internet-facing: re-key, revoke, reissue.",
               "Force password/session resets for affected applications after patching."],
     "commands": [{"label": "Definitive NSE validation", "cmd": "nmap -sV --script ssl-heartbleed -p {PORT} {HOST}"},
                  {"label": "Inspect the certificate", "cmd": "openssl s_client -connect {HOST}:{PORT} </dev/null 2>/dev/null | openssl x509 -noout -dates -subject"}],
     "remediation": "Upgrade OpenSSL to a supported 3.x, restart all linked services, and rotate certificates/keys."},
    {"id": "ghostcat", "cves": ["CVE-2020-1938"], "patterns": [r"ghostcat|ajp|tomcat"],
     "title": "Ghostcat — Tomcat AJP file read / possible RCE", "severity": "High",
     "summary": "The AJP connector (default 8009) trusted any connection; an attacker who can reach it can read files inside webapps (including WEB-INF config and credentials) and, with an upload feature, chain to RCE.",
     "tools": ["nmap (ajp NSE scripts)", "searchsploit"],
     "steps": ["Check whether 8009/tcp is reachable from your vantage point — reachability is the key precondition.",
               "Enumerate AJP methods with the NSE ajp scripts.",
               "In a lab, use the public checker to read a harmless file (e.g. /WEB-INF/web.xml) as evidence.",
               "If AJP is unused (common), the fix is simply to disable it."],
     "commands": [{"label": "AJP enumeration", "cmd": "nmap -sV --script ajp-methods,ajp-headers -p 8009 {HOST}"},
                  {"label": "Public checker reference", "cmd": "searchsploit ghostcat"}],
     "remediation": "Disable the AJP connector, or bind it to localhost and set a strong secret; upgrade Tomcat."},
    {"id": "log4shell", "cves": ["CVE-2021-44228"], "patterns": [r"log4j|log4shell"],
     "title": "Log4Shell — Log4j JNDI unauthenticated RCE", "severity": "Critical",
     "summary": "Log4j 2.0–2.14.1 evaluates JNDI lookups in logged strings; any field the application logs (User-Agent, headers, usernames) can trigger an LDAP callback and code execution. Banner data rarely proves it — you validate with a canary callback.",
     "tools": ["interactsh / Burp Collaborator (canary)", "curl", "vendor scanners"],
     "steps": ["Identify Java services likely to log request data (web apps, APIs, Elasticsearch, etc.).",
               "Send a unique canary JNDI payload in several headers/fields to YOUR OWN callback server and watch for DNS/LDAP lookups.",
               "A callback proves the vulnerable code path executes lookups; no callback is suggestive but not conclusive (egress may be filtered).",
               "Also inventory shaded/embedded log4j copies in deployed artefacts — patching the obvious app is not enough."],
     "commands": [{"label": "Start a canary listener (your own server)", "cmd": "interactsh-client -v"},
                  {"label": "Send a canary probe in headers", "cmd": "curl -s -H 'User-Agent: ${jndi:ldap://{CANARY}/x}' http://{HOST}/ -o /dev/null -w '%{http_code}'"}],
     "remediation": "Upgrade Log4j to 2.17.1+ (or remove JndiLookup), and audit all Java artefacts including dependencies of dependencies."},
    {"id": "exchange-proxy", "cves": ["CVE-2021-26855", "CVE-2021-34473"], "patterns": [r"exchange|proxylogon|proxyshell"],
     "title": "ProxyLogon / ProxyShell — Exchange unauthenticated RCE chains", "severity": "Critical",
     "summary": "SSRF (ProxyLogon) or path-confusion (ProxyShell) chains give unauthenticated attackers an Exchange admin shell and were mass-exploited for webshell deployment. Version/CU level is the primary triage signal.",
     "tools": ["Microsoft's official CU/SU checker", "nmap http NSE scripts", "IoC hunting (webshells in wwwroot)"],
     "steps": ["Get the exact Exchange version + CU/SU level and compare against the fixed builds.",
               "Run Microsoft's HealthChecker on the server for an authoritative result.",
               "Hunt for compromise artefacts (webshells in aspnet_client / inetpub, suspicious .aspx timestamps) — exploitation was widespread, so 'patched now' is not 'was never breached'.",
               "Check mailbox audit logs for the exploitation window if the host was exposed unpatched."],
     "commands": [{"label": "Fingerprint the Exchange build", "cmd": "curl -sk https://{HOST}/owa/ | grep -i -o 'OWA[^<]*' | head"},
                  {"label": "On the server: Microsoft HealthChecker", "cmd": "powershell -File .\\HealthChecker.ps1 -BuildHtmlServersReport"}],
     "remediation": "Apply the latest CU + SU, run HealthChecker clean, and complete an IoC sweep before declaring the host safe."},
    {"id": "confluence-ognl", "cves": ["CVE-2022-26134", "CVE-2021-26084"], "patterns": [r"confluence"],
     "title": "Confluence OGNL — unauthenticated RCE", "severity": "Critical",
     "summary": "An OGNL injection in Confluence Server/Data Center allows unauthenticated attackers to execute code as the Confluence user, including creating new admin accounts. Internet-facing Confluence was exploited in the wild within days.",
     "tools": ["curl (version footer)", "searchsploit"],
     "steps": ["Confirm Confluence version from the login page footer/meta against affected ranges.",
               "Check whether the instance is internet-facing and whether the vendor workaround (xwork jar) was applied.",
               "Look for newly created admin accounts and unknown plugins — post-exploitation persistence is common with this CVE.",
               "Validate exploitability only in a lab clone; version + exposure is sufficient production evidence."],
     "commands": [{"label": "Get the Confluence version", "cmd": "curl -s http://{HOST}/login.action | grep -i -o 'version[^<]*' | head -3"},
                  {"label": "Public references", "cmd": "searchsploit confluence ognl"}],
     "remediation": "Upgrade Confluence to a fixed release, audit admin users/plugins, and restrict access to trusted networks/VPN."},
    {"id": "smart-install", "cves": ["CVE-2018-0171"], "patterns": [r"smart install"],
     "title": "Cisco Smart Install — unauthenticated config/RCE (4786)", "severity": "Critical",
     "summary": "The Smart Install client on Cisco IOS/IOS XE accepts unauthenticated messages on tcp/4786 that can replace the device configuration or execute code. It is enabled by default on many switches and should almost never be on in production.",
     "tools": ["nmap (4786 version scan)", "SIET (lab reference)"],
     "steps": ["Confirm 4786/tcp is open and the device is a Cisco switch/router.",
               "On the device, check 'show vstack config' — Smart Install client enabled = exposed.",
               "Treat unexpected config changes on such devices as potential compromise indicators.",
               "Disable with 'no vstack' — there is rarely an operational reason to keep it."],
     "commands": [{"label": "Confirm the port is listening", "cmd": "nmap -sV -p 4786 {HOST}"},
                  {"label": "On the device CLI", "cmd": "show vstack config"}],
     "remediation": "Disable Smart Install ('no vstack') on every device that is not actively being provisioned."},
    {"id": "proftpd-modcopy", "cves": ["CVE-2015-3306"], "patterns": [r"proftpd 1\.3\.5"],
     "title": "ProFTPD 1.3.5 mod_copy — unauthenticated file copy", "severity": "High",
     "summary": "ProFTPD 1.3.5's mod_copy allows unauthenticated SITE CPFR/CPTO commands, copying files anywhere the FTP user can write — classically used to drop a web shell into the web root.",
     "tools": ["ftp client / telnet", "searchsploit"],
     "steps": ["Confirm version 1.3.5 and that mod_copy responds to SITE commands without authentication.",
               "In a lab, copy a harmless file to prove the primitive; on production the unauthenticated SITE response is enough evidence.",
               "Check the web root and FTP-writable paths for planted files if the service was exposed."],
     "commands": [{"label": "Probe mod_copy without auth (lab)", "cmd": "printf 'SITE CPFR /etc/hosts\\nSITE CPTO /tmp/copy_test\\n' | nc {HOST} 21"},
                  {"label": "Public exploit reference", "cmd": "searchsploit proftpd 1.3.5"}],
     "remediation": "Upgrade ProFTPD, disable mod_copy if unused, and never co-locate FTP-writable paths with the web root."},
    {"id": "drupalgeddon", "cves": ["CVE-2018-7600"], "patterns": [r"drupal"],
     "title": "Drupalgeddon2 — Drupal unauthenticated RCE", "severity": "Critical",
     "summary": "A render-array flaw in Drupal core (6/7/8) gives unauthenticated remote code execution and was mass-exploited by cryptomining botnets within hours. Any unpatched Drupal of that era should be assumed compromised.",
     "tools": ["curl (CHANGELOG/version files)", "searchsploit", "drupwn (enumeration)"],
     "steps": ["Determine the exact Drupal core version (CHANGELOG.txt or generator meta on older installs).",
               "Compare against fixed versions (7.58 / 8.5.1 / 8.4.6 / 8.3.9).",
               "Assume compromise if it was internet-facing and unpatched in 2018: audit files, cron entries, and admin users.",
               "Rebuild from clean source + database review is the vendor-recommended path for exposed hosts."],
     "commands": [{"label": "Check core version markers", "cmd": "curl -s http://{HOST}/CHANGELOG.txt | head -5"},
                  {"label": "Public exploit reference", "cmd": "searchsploit drupalgeddon"}],
     "remediation": "Upgrade Drupal core immediately; if the host was exposed unpatched, follow the assume-breach rebuild guidance."},
    {"id": "exim-rce", "cves": ["CVE-2019-10149", "CVE-2020-28007"], "patterns": [r"exim"],
     "title": "Exim — pre-auth RCE generations (WIZard / 21Nails)", "severity": "High",
     "summary": "Exim has had repeated unauthenticated RCEs (CVE-2019-10149 'Return of the WIZard', the 21Nails set). The SMTP banner gives the exact version, making triage straightforward.",
     "tools": ["nmap smtp NSE scripts", "searchsploit"],
     "steps": ["Read the exact Exim version from the 220 banner.",
               "Map it against the affected ranges for 10149 (< 4.92) and the 21Nails set (< 4.94.2).",
               "Check the host for the usual persistence artefacts if it was internet-facing (cron, authorized_keys, setuid files).",
               "Mail servers are high-value; schedule the upgrade as an emergency change if in range."],
     "commands": [{"label": "Read the SMTP banner", "cmd": "nmap -sV --script smtp-commands -p 25 {HOST}"},
                  {"label": "Public references", "cmd": "searchsploit exim"}],
     "remediation": "Upgrade Exim to the latest stable; restrict SMTP submission and keep the banner version current."},
    # --- misconfiguration guides (no single CVE) ---
    {"id": "redis-unauth", "cves": [], "patterns": [r"redis"],
     "title": "Redis exposed — unauthenticated data & RCE paths", "severity": "Critical",
     "summary": "Redis historically needs no password: anyone who can connect can read/write all data, and via CONFIG SET dir + SAVE write files (SSH keys, cron) or use replication for code execution. Exposure on a network interface is the finding.",
     "tools": ["redis-cli", "nmap redis-info NSE"],
     "steps": ["Connect with redis-cli and run INFO — a response without AUTH proves no authentication.",
               "Check CONFIG GET for dir/dbfilename and protected-mode settings.",
               "Enumerate keys carefully (SCAN, not KEYS on production) to assess data exposure.",
               "Do NOT write test keys/files on production without written approval — read-only INFO is your evidence."],
     "commands": [{"label": "Prove no-auth (read-only INFO)", "cmd": "redis-cli -h {HOST} -p {PORT} INFO server | head -5"},
                  {"label": "NSE info check", "cmd": "nmap -sV --script redis-info -p {PORT} {HOST}"}],
     "remediation": "Set requirepass, bind to localhost/private interfaces, enable protected mode, and firewall the port."},
    {"id": "mongo-unauth", "cves": [], "patterns": [r"mongo"],
     "title": "MongoDB exposed — unauthenticated database access", "severity": "High",
     "summary": "MongoDB instances bound to all interfaces without auth have caused mass data theft/ransom. The validation is a read-only connection attempt and database listing.",
     "tools": ["mongosh / mongo shell", "nmap mongodb NSE scripts"],
     "steps": ["Attempt a read-only connection; list databases with show dbs.",
               "If databases list without credentials, authentication is off — full read/write must be assumed.",
               "Check bindIp in mongod.conf and whether the port is reachable beyond the app tier.",
               "Look for ransom notes (_PLEASE_READ_ME_ style databases) in the listing."],
     "commands": [{"label": "List databases (read-only check)", "cmd": "mongosh --host {HOST} --port {PORT} --eval 'db.adminCommand({listDatabases:1})'"},
                  {"label": "NSE database info", "cmd": "nmap -sV --script mongodb-info,mongodb-databases -p {PORT} {HOST}"}],
     "remediation": "Enable authentication, bind to private interfaces only, and require TLS for remote connections."},
    {"id": "docker-api", "cves": [], "patterns": [r"docker"],
     "title": "Docker API exposed — unauthenticated host-root equivalent", "severity": "Critical",
     "summary": "The Docker daemon API on 2375 (cleartext, unauthenticated) gives full control of containers — and therefore the host: mounting / into a container is instant root. This is one of the most reliably exploited exposures in the wild (cryptomining).",
     "tools": ["curl", "docker CLI (remote host)"],
     "steps": ["Query the API version endpoint — a JSON response proves the unauthenticated API.",
               "List containers/images read-only to assess what is already running (look for unknown miners).",
               "Do NOT start containers on production as 'proof' — the API response is complete evidence.",
               "Check 2376 too: TLS without client-cert verification is the same problem."],
     "commands": [{"label": "Prove the API answers (read-only)", "cmd": "curl -s http://{HOST}:2375/version | head -20"},
                  {"label": "List running containers (read-only)", "cmd": "curl -s http://{HOST}:2375/containers/json"}],
     "remediation": "Never expose 2375. Use the local socket or 2376 with mutual TLS and source-IP restrictions."},
    {"id": "elastic-unauth", "cves": [], "patterns": [r"elasticsearch"],
     "title": "Elasticsearch exposed — unauthenticated data access", "severity": "High",
     "summary": "Clusters before security-by-default (pre-7.x free tier, or security disabled) answer cluster and index APIs without credentials — the root cause of many public breach dumps.",
     "tools": ["curl", "nmap (9200 version scan)"],
     "steps": ["Query the cluster info endpoint — JSON with cluster_name proves an open API.",
               "List indices read-only to gauge data exposure (names/counts only).",
               "Check whether X-Pack security is enabled (a 401 means auth IS on — good).",
               "Review snapshot repositories and remote cluster settings for persistence."],
     "commands": [{"label": "Cluster info (read-only)", "cmd": "curl -s http://{HOST}:9200/"},
                  {"label": "Index listing (read-only)", "cmd": "curl -s http://{HOST}:9200/_cat/indices?v | head"}],
     "remediation": "Enable security (auth + TLS), bind to the private network, and audit exposed data for breach notification duties."},
    {"id": "ftp-anon", "cves": [], "patterns": [r"anonymous ftp|ftp-anon"],
     "title": "Anonymous FTP login allowed", "severity": "High",
     "summary": "Anonymous FTP lets anyone list/download (and sometimes upload) files. Upload access turns the server into malware/drop hosting; read access routinely leaks backups and configs.",
     "tools": ["ftp client", "nmap ftp-anon NSE"],
     "steps": ["Log in as anonymous with any email as password and list the root directory.",
               "Test WRITE access only with an agreed harmless filename in scope; read-only listing is usually sufficient evidence.",
               "Inventory downloadable content for sensitive files (backups, configs, exports).",
               "Check whether the FTP tree overlaps the web root (upload → webshell chain)."],
     "commands": [{"label": "NSE anonymous check", "cmd": "nmap -sV --script ftp-anon -p 21 {HOST}"},
                  {"label": "Manual anonymous login", "cmd": "ftp -n {HOST}  # then: user anonymous test@test  ·  ls"}],
     "remediation": "Disable anonymous login; if public file distribution is required, use a hardened HTTPS repository instead."},
    {"id": "snmp-default", "cves": [], "patterns": [r"snmp"],
     "title": "SNMP default communities / v1-v2c exposure", "severity": "Medium",
     "summary": "SNMPv1/v2c with 'public'/'private' communities leaks full device configuration (and 'private' often allows SET — configuration changes). It is also a top source of network maps for attackers.",
     "tools": ["snmpwalk", "onesixtyone"],
     "steps": ["Try a read-only walk with the 'public' community — a response proves the default is live.",
               "Enumerate what is visible: interfaces, routing, ARP tables, software versions.",
               "Check for a writable community only in scope (SET tests change state — get approval).",
               "Inventory every device answering on 161/udp, not just this host."],
     "commands": [{"label": "Read-only walk with default community", "cmd": "snmpwalk -v2c -c public {HOST} 1.3.6.1.2.1.1 | head"},
                  {"label": "Community sweep of a range (lab)", "cmd": "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {HOST}"}],
     "remediation": "Move to SNMPv3 (authPriv), remove default communities, and restrict 161/udp to the NMS."},
    {"id": "telnet-cleartext", "cves": [], "patterns": [r"telnet"],
     "title": "Telnet — cleartext remote administration", "severity": "High",
     "summary": "Telnet sends credentials and session content in cleartext and is a favourite initial-access service on network devices and legacy servers. Its presence alone is the finding.",
     "tools": ["nmap version scan", "Wireshark (to demonstrate sniffing in a lab)"],
     "steps": ["Confirm the service is Telnet (banner on 23/tcp).",
               "Identify the device/service owner and what is administered through it.",
               "In a lab, demonstrate credential capture on a mirrored port to make the risk concrete for the owner.",
               "Verify an SSH replacement exists before recommending immediate shutdown on production gear."],
     "commands": [{"label": "Confirm the Telnet banner", "cmd": "nmap -sV -p 23 {HOST}"},
                  {"label": "Check SSH is available as replacement", "cmd": "nmap -sV -p 22 {HOST}"}],
     "remediation": "Disable Telnet and administer via SSH with key authentication."},
    {"id": "vnc-exposed", "cves": [], "patterns": [r"vnc"],
     "title": "VNC exposed — weak-auth remote desktop", "severity": "High",
     "summary": "VNC's classic authentication is an 8-character DES challenge — effectively brute-forceable — and sessions are unencrypted. An exposed VNC port should be treated as an exposed desktop.",
     "tools": ["nmap (vnc-info, rfb NSE scripts)", "a VNC viewer (lab)"],
     "steps": ["Run vnc-info to read the server's security types — type 1 (None) means no authentication at all.",
               "Record the desktop title/version the server leaks in the handshake.",
               "Do not attempt password guessing on production without written approval.",
               "Check what the desktop session is — an unlocked admin desktop multiplies the impact."],
     "commands": [{"label": "Read VNC security types", "cmd": "nmap -sV --script vnc-info -p {PORT} {HOST}"}],
     "remediation": "Tunnel VNC over SSH/VPN, set a strong password, or replace with a modern remote-access gateway."},
]

def _guide_for(cve_field, blob):
    for g in GUIDES:
        for c in g["cves"]:
            if c and c in (cve_field or ""): return g
    for g in GUIDES:
        for pat in g["patterns"]:
            if re.search(pat, blob or "", re.I): return g
    return None

def build_guides(findings, exploits):
    """One guide card per (host, port, guide) that matches the results."""
    out, seen = [], set()
    def emit(host, hostname, port, service, cve_field, blob, severity):
        g = _guide_for(cve_field, blob)
        if not g: return
        key = (host, port, g["id"])
        if key in seen: return
        seen.add(key)
        cmds = [{"label": c["label"],
                 "cmd": c["cmd"].replace("{HOST}", host).replace("{PORT}", str(port or ""))}
                for c in g["commands"]]
        out.append({"host": host, "hostname": hostname, "port": port, "service": service,
                    "guide_id": g["id"], "title": g["title"],
                    "cve": next((c for c in g["cves"] if c in (cve_field or "")), g["cves"][0] if g["cves"] else ""),
                    "severity": severity if severity in SEVERITIES else g["severity"],
                    "cvss": CVSS_KNOWN.get(next((c for c in g["cves"] if c in (cve_field or "")), ""), None),
                    "summary": g["summary"], "tools": g["tools"], "steps": g["steps"],
                    "commands": cmds, "remediation": g["remediation"]})
    for e in exploits:
        emit(e.host, "", e.port, e.service, e.cve, f"{e.title} {e.service}", e.severity)
    for f in findings:
        emit(f.host, f.hostname, f.port, f.service, f.cve,
             f"{f.title} {f.service} {f.banner} {f.category}", f.severity)
    out.sort(key=lambda x: (SEV_RANK[x["severity"]], x["host"], x["port"]))
    return out

def build_cves(findings, exploits):
    """Aggregate every CVE id mentioned anywhere into one record per CVE."""
    agg = {}
    def note(cve, host, port, service, severity, title, source, conf=""):
        if not cve: return
        r = agg.setdefault(cve, {"cve": cve, "title": "", "severity": "Info", "cvss": CVSS_KNOWN.get(cve),
                                 "hosts": set(), "ports": set(), "services": set(), "sources": set(),
                                 "description": "", "conf": set()})
        if host: r["hosts"].add(host)
        if port: r["ports"].add(port)
        if service: r["services"].add(service)
        if source: r["sources"].add(source)
        if conf: r["conf"].add(conf)
        if SEV_RANK.get(severity, 9) < SEV_RANK.get(r["severity"], 9): r["severity"] = severity
        if title and (not r["title"] or len(title) < len(r["title"])): r["title"] = title
    for e in exploits:
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", e.cve or ""):
            note(cve, e.host, e.port, e.service, e.severity, e.title, e.source, e.confidence or ("NSE script" if "NSE" in (e.source or "") else "Built-in rule"))
    for f in findings:
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", (f.cve or "") + " " + (f.title or "")):
            note(cve, f.host, f.port, f.service, f.severity, f.title, f.category, f.confidence or ("NSE script" if "NSE" in (f.category or "") else "Built-in rule"))
    guides = build_guides(findings, exploits)
    by_cve = {}
    for g in guides:
        if g["cve"]: by_cve.setdefault(g["cve"], g)
    kb_by_cve = {}
    for g in GUIDES:
        for c in g["cves"]: kb_by_cve.setdefault(c, g)
    out = []
    for cve, r in agg.items():
        g = by_cve.get(cve); kb = kb_by_cve.get(cve)
        info = INTEL.cve_info(cve) if INTEL else {}
        cvss = info.get("cvss") if info.get("cvss") is not None else r["cvss"]
        conf = sorted(r["conf"], key=lambda c: CONF_RANK.get(c, 9))
        has_x = any(cve in (e.cve or "") for e in exploits)
        rec = {"cve": cve, "title": (g["title"] if g else (kb["title"] if kb else r["title"])) or cve,
               "severity": r["severity"], "cvss": cvss,
               "description": (g["summary"] if g else (kb["summary"] if kb else "")) or info.get("descr", ""),
               "has_guide_kb": bool(g or kb),
               "hosts": sorted(r["hosts"]), "ports": sorted(r["ports"]),
               "services": sorted(r["services"]), "sources": sorted(r["sources"]),
               "host_count": len(r["hosts"]), "has_guide": bool(g or kb),
               "kev": bool(info.get("kev")), "kev_name": (info.get("kev") or {}).get("name", ""),
               "ransomware": (info.get("kev") or {}).get("ransomware", ""),
               "epss": info.get("epss"), "epss_pct": info.get("epss_pct"),
               "edb": [e["edb"] for e in info.get("edb", [])], "msf": [m["module"] for m in info.get("msf", [])],
               "confidence": conf[0] if conf else "Built-in rule"}
        rec["priority"] = priority_of({"kev": rec["kev"], "edb": rec["edb"] or (["x"] if has_x else []),
                                       "msf": rec["msf"], "epss": rec["epss"], "cvss": cvss})
        out.append(rec)
    out.sort(key=lambda x: (x["priority"], SEV_RANK[x["severity"]], -(x["cvss"] or 0), x["cve"]))
    return out

def build_dataset(hosts, findings, exploits, metas):
    sev_counts = Counter(f.severity for f in findings)
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": f"Nmapilizer {VERSION}", "intel": (INTEL.summary() if INTEL else None), "author": {"name": AUTHOR_NAME, "links": dict(AUTHOR_LINKS)}, "scans": metas,
        "totals": {"hosts": len(hosts), "hosts_up": sum(1 for h in hosts.values() if h.status == "up"),
                   "open_ports": sum(len(h.open_ports) for h in hosts.values()),
                   "findings": len(findings), "exploits": len(exploits),
                   "flagged_hosts": len({f.host for f in findings if f.severity in ("Critical", "High", "Medium")}),
                   "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES}},
        "hosts": [{"ip": h.ip, "hostname": h.display_name, "hostnames": h.hostnames,
                   "status": h.status, "os": h.os_name, "os_accuracy": h.os_accuracy,
                   "mac": h.mac, "vendor": h.vendor, "risk_score": h.risk_score,
                   "risk_level": h.risk_level, "sources": h.sources,
                   "ports": [{"protocol": p.protocol, "port": p.portid, "state": p.state,
                              "service": p.service, "product": p.product, "version": p.version,
                              "extrainfo": p.extrainfo, "banner": p.banner, "tunnel": p.tunnel,
                              "cpes": p.cpes, "scripts": p.scripts} for p in
                             sorted(h.ports.values(), key=lambda x: (x.protocol, x.portid))],
                   "scripts": h.scripts} for h in hosts.values()],
        "findings": [asdict(f) for f in findings],
        "exploits": [asdict(e) for e in exploits],
        "guides": build_guides(findings, exploits),
        "cves": build_cves(findings, exploits),
    }

# --------------------------------------------------------------------------
# REPORT — shared CSS / JS (also used, inlined, by the live dashboard)
# --------------------------------------------------------------------------
CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2b3446;--txt:#e6edf3;--mut:#8b98ab;
--crit:#e5484d;--high:#f76b15;--med:#ffb224;--low:#46a758;--info:#6e7f96;--acc:#3fb6f2;
--hover:#1a2130;--codebg:#0a0d12;--codefg:#ffd479;--onacc:#06222f;--shadow:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28);
--fg:var(--txt);--danger:#ff8080;color-scheme:dark}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
header{padding:22px 28px 10px}h1{margin:0 0 4px;font-size:26px}h2{font-size:19px;margin:22px 0 10px}
h3{font-size:15px;margin:16px 0 6px}.mut{color:var(--mut)}.small{font-size:12px}
.wrap{max-width:1380px;margin:0 auto;padding:0 20px 50px}
nav{display:flex;gap:8px;flex-wrap:wrap;padding:10px 28px;border-bottom:1px solid var(--line)}
nav a{padding:6px 12px;border:1px solid var(--line);border-radius:20px;color:var(--txt);background:var(--panel)}
nav a.on{background:var(--acc);color:var(--onacc);border-color:var(--acc);font-weight:700}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
.card b{font-size:26px;display:block}.card span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;box-shadow:var(--shadow)}
th,td{padding:8px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:var(--panel2);font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);cursor:pointer;white-space:nowrap}
tr:hover td{background:var(--hover)}code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--codefg);word-break:break-word}
.pill{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11.5px;font-weight:800;letter-spacing:.03em;color:#0b0e13;white-space:nowrap;border:1px solid rgba(255,255,255,.28);text-shadow:none}
.pill.Critical,.p-Critical{background:#e5484d;color:#fff}
.pill.High,.p-High{background:#f76b15;color:#fff}
.pill.Medium,.p-Medium{background:#ffb224;color:#231a00}
.pill.Low,.p-Low{background:#46a758;color:#fff}
.pill.Info,.p-Info{background:#5b7a99;color:#fff}
.pill.Clean,.p-Clean{background:#46a758;color:#fff}
.risk{display:inline-block;min-width:32px;text-align:center;padding:1px 8px;border-radius:20px;font-weight:800;font-size:12px;color:#fff;background:#5b7a99}
.risk.r3{background:#e5484d}.risk.r2{background:#f76b15}.risk.r1{background:#ffb224;color:#231a00}.risk.r0{background:#46a758}
.bar{height:10px;background:var(--panel2);border:1px solid var(--line);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
input[type=search],select{background:var(--panel);border:1px solid var(--line);color:var(--txt);
padding:9px 12px;border-radius:9px;min-width:240px} .tools{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0;align-items:center}
.finding{border-left:5px solid var(--info);background:var(--panel);border-radius:8px;padding:12px 16px;margin:10px 0}
.finding.Critical{border-color:var(--crit)}.finding.High{border-color:var(--high)}
.finding.Medium{border-color:var(--med)}.finding.Low{border-color:var(--low)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--codebg);color:var(--codefg);border:1px solid var(--line);border-radius:8px;padding:10px;font-size:12px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px}
footer{color:var(--mut);font-size:12px;padding:20px 28px;border-top:1px solid var(--line)}
.drop{border:2px dashed var(--line);border-radius:14px;padding:26px;text-align:center;color:var(--mut);margin:14px 0}
.drop.over{border-color:var(--acc);color:var(--txt);background:var(--panel)}
.drawer{position:fixed;top:0;right:0;width:min(680px,96vw);height:100vh;overflow:auto;background:var(--panel);
border-left:1px solid var(--line);padding:20px 24px;z-index:50;box-shadow:-12px 0 40px #0008}
.hidden{display:none}button{background:var(--acc);color:var(--onacc);border:0;padding:9px 16px;border-radius:9px;font-weight:700;cursor:pointer}
::selection{background:var(--acc);color:var(--onacc)}
:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
tbody tr{transition:background .08s ease}
button.ghost{background:var(--panel2);color:var(--txt);border:1px solid var(--line)}
@media(max-width:700px){header,.wrap{padding-left:12px;padding-right:12px}table{font-size:12.5px}}

/* ===== v4: fonts, icons, no-wrap, tables, topology, logs ===== */
body{font-family:'Inter',-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
code,pre,.mono{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace}
.ms{font-family:'Material Symbols Outlined';font-weight:normal;font-style:normal;line-height:1;
letter-spacing:normal;text-transform:none;display:inline-block;white-space:nowrap;word-wrap:normal;
direction:ltr;-webkit-font-smoothing:antialiased;font-feature-settings:'liga' 1;font-size:22px;vertical-align:-5px}
td .nw, th .nw, .nw{white-space:nowrap}
td.ipcell, td.portcell{white-space:nowrap}
.tblwrap{position:relative;overflow:hidden;border-radius:10px;margin:0 0 14px}html,body{overflow-x:hidden;max-width:100%}
.tblwrap table{margin:0}
.copybtn{position:absolute;top:8px;right:8px;z-index:5;opacity:0;pointer-events:none;transition:opacity .15s;
background:var(--panel2);color:var(--txt);border:1px solid var(--line);padding:5px 10px;border-radius:8px;font-size:12px}
.tblwrap:hover .copybtn{opacity:1;pointer-events:auto}
.topbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.topbar select,.topbar input{background:var(--panel);border:1px solid var(--line);color:var(--txt);padding:8px 10px;border-radius:9px}
.filterbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:var(--panel);
border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin:12px 0}
.filterbar select,.filterbar input{background:var(--bg);border:1px solid var(--line);color:var(--txt);padding:7px 9px;border-radius:8px;min-width:0}
.filterbar label{font-size:11px;color:var(--mut);display:flex;flex-direction:column;gap:2px;text-transform:uppercase;letter-spacing:.04em}
#logPanel{background:#050807;border:1px solid var(--line);border-radius:12px;margin:18px 0;padding:10px 14px;
font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;color:#9fe8b1;max-height:190px;overflow:auto}
#logPanel .lt{color:#5b7a63}
#topoOuter{overflow:auto;border:1px solid var(--line);border-radius:14px;background:
radial-gradient(circle at 1px 1px, var(--line) 1px, transparent 0);background-size:26px 26px;background-color:var(--panel);
height:560px;cursor:grab}
#topoOuter:active{cursor:grabbing}
#topoWorld{transform-origin:0 0;padding:18px;min-width:900px}
.zone{border:1.5px dashed var(--acc);border-radius:14px;padding:12px 14px;margin:0 0 18px;background:color-mix(in srgb, var(--panel) 88%, transparent)}
.zone h3{margin:0 0 10px;font-size:14px}
.nodes{display:flex;flex-wrap:wrap;gap:12px}
.node{width:104px;text-align:center;background:var(--panel2);border:1.5px solid var(--line);border-radius:12px;
padding:9px 4px 7px;cursor:pointer}
.node:hover{border-color:var(--acc)}
.node .ms{font-size:32px}
.node .ip{font-family:'JetBrains Mono',monospace;font-size:10.5px;white-space:nowrap}
.node .hn{font-size:10px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node .dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.cmdrow{display:flex;gap:8px;align-items:flex-start;margin:6px 0}
.cmdrow code{flex:1;background:var(--codebg);color:var(--codefg);padding:8px 10px;border-radius:8px;border:1px solid var(--line);white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
@media print{nav,.tools,.filterbar,.drop,#logPanel,.copybtn{display:none!important}}

/* ===== v6: form controls + text readability in every theme ===== */
option,optgroup{background:var(--panel);color:var(--txt)}
::placeholder{color:var(--mut);opacity:.85}
input,select,textarea,button{font-family:inherit}
.mut{color:var(--mut)}
a{color:var(--acc)}
.pill.P1,.p-P1{background:#e5484d;color:#fff}
.pill.P2,.p-P2{background:#f76b15;color:#fff}
.pill.P3,.p-P3{background:#ffb224;color:#231a00}
.pill.P4,.p-P4{background:#5b7a99;color:#fff}
/* ===== v6.0.1: report author buttons + faithful print/PDF colours ===== */
html{background:var(--bg)}
.socbtns{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:10px 0 2px}
.socbtn{display:inline-flex;align-items:center;gap:7px;padding:6px 13px;border:1px solid var(--line);border-radius:99px;background:var(--panel);color:var(--txt);font-size:12.5px;font-weight:600;text-decoration:none;transition:transform .25s cubic-bezier(.34,1.56,.64,1),background .18s,color .18s,border-color .18s}
.socbtn svg{width:15px;height:15px}.socbtn svg .cut{fill:var(--panel)}
.socbtn:hover{transform:translateY(-2px);background:var(--acc);color:var(--onacc);border-color:var(--acc);text-decoration:none}
.socbtn:hover svg .cut{fill:var(--acc)}
.socby{color:var(--mut);font-size:12px;margin-left:4px}.socby b{color:var(--txt)}
.printbar{background:var(--acc);color:var(--onacc);text-align:center;padding:9px 12px;font-weight:700;font-size:13px}
.printbar button{margin-left:10px;background:var(--onacc);color:var(--acc);border:0;border-radius:8px;padding:5px 12px;font-weight:700;cursor:pointer}
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}.noprint{display:none!important}@page{margin:10mm}}
/* ===== v6: author card / social icons ===== */
.authorcard{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}
.authortxt{display:flex;flex-direction:column;line-height:1.15}
.authortxt b{font-size:16px;letter-spacing:.01em}
.socrow,.authorline{display:inline-flex;align-items:center;gap:6px}
.authorline b{margin-right:4px;color:var(--txt)}
a.soc{width:30px;height:30px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:var(--txt);background:var(--panel);border:1px solid var(--line);text-decoration:none;transition:transform .28s cubic-bezier(.34,1.56,.64,1),background .18s,color .18s,border-color .18s}
a.soc svg{width:15px;height:15px}
a.soc svg .cut{fill:var(--panel)}
a.soc:hover{transform:translateY(-4px) scale(1.12);background:var(--acc);color:var(--onacc);border-color:var(--acc);text-decoration:none}
a.soc:hover svg .cut{fill:var(--acc)}
footer .authorline{margin-left:8px;vertical-align:middle}
footer a.soc{width:24px;height:24px}footer a.soc svg{width:12px;height:12px}
.shimmer{background:linear-gradient(90deg,var(--txt) 35%,var(--acc) 50%,var(--txt) 65%);background-size:250% 100%;-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent;animation:shimmer 5s linear infinite}
@keyframes shimmer{0%{background-position:150% 0}100%{background-position:-100% 0}}
@media(prefers-reduced-motion:reduce){.shimmer{animation:none;-webkit-text-fill-color:var(--txt);color:var(--txt);background:none}a.soc{transition:none}}
"""
JS = """
function filterTable(inputId, tableId){
  const q=document.getElementById(inputId).value.toLowerCase();
  document.querySelectorAll('#'+tableId+' tbody tr').forEach(tr=>{
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';});
}
function sortTable(th){
  const table=th.closest('table'), idx=[...th.parentNode.children].indexOf(th);
  const rows=[...table.querySelectorAll('tbody tr')]; const asc = th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
  rows.sort((a,b)=>{let x=a.children[idx]?.textContent.trim()||'', y=b.children[idx]?.textContent.trim()||'';
    const nx=parseFloat(x), ny=parseFloat(y);
    const c=(!isNaN(nx)&&!isNaN(ny)) ? nx-ny : x.localeCompare(y,undefined,{numeric:true});
    return asc?c:-c;});
  rows.forEach(r=>table.querySelector('tbody').appendChild(r));
}
document.querySelectorAll('th').forEach(th=>th.addEventListener('click',()=>sortTable(th)));
function filterSev(sel, cls){
  const v=sel.value;
  document.querySelectorAll('.'+cls).forEach(el=>{ el.style.display = (!v||el.dataset.sev===v)?'':'none'; });
}
"""

def _page(title, active, body, title_main="Nmapilizer Report"):
    nav = [("index.html", "Dashboard"), ("hosts.html", "Hosts"), ("ports.html", "Ports"),
           ("findings.html", "Findings"), ("exploits.html", "Exploits"), ("guides.html", "Exploit Guides"),
           ("cves.html", "CVEs")]
    nav_html = "".join(f'<a href="{href}" class="{"on" if href==active else ""}">{label}</a>' for href, label in nav)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="author" content="{AUTHOR_NAME}"><title>{esc(title)} — Nmapilizer</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"><link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap" rel="stylesheet"><link rel="stylesheet" href="assets/style.css"></head>
<body><header><h1>🔎 {esc(title_main)}</h1><div class="mut">{esc(title)}</div>{author_buttons()}</header>
<nav>{nav_html}</nav>{REPORT_TOP_BANNER}<div class="wrap">{body}</div>
<footer>Nmapilizer {VERSION} · Passive analysis of Nmap XML you supplied — nothing was scanned by this tool.
Verify every Critical/High finding manually before acting. Use only on networks you own or are authorised to assess.
<br>Author: {author_html(compact=True)}</footer>
<script src="assets/app.js"></script></body></html>"""

def _sev_pill(s): return f'<span class="pill p-{esc(s)}">{esc(s)}</span>'
def _score_bar(score):
    color = SEV_COLOR.get("Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 20 else "Low", "#46a758")
    return f'<div class="bar" title="{score}/100"><i style="width:{score}%;background:{color}"></i></div>{score}/100'

REPORT_TOP_BANNER = ""

CVE_HEAD = ("<th>CVE</th><th>Priority</th><th>Name</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>EPSS</th>"
            "<th>Exploits</th><th>Confidence</th><th>Affected hosts</th><th>Ports</th><th>Services</th>")
def _xpl_txt(c):
    a = []
    if c.get("edb"): a.append(f"EDB {len(c['edb'])}")
    if c.get("msf"): a.append(f"MSF {len(c['msf'])}")
    return " · ".join(a) or "—"
def _cve_table_rows(cves, guide=True):
    rows = []
    for c in cves:
        kev = '<span class="pill p-Critical">KEV</span>' if c.get("kev") else "—"
        epss = f'{c["epss"] * 100:.1f}%' if c.get("epss") is not None else "—"
        cvss = c["cvss"] if c.get("cvss") is not None else "—"
        extra = f'<td>{"Yes" if c.get("has_guide") else "—"}</td>' if guide else ""
        rows.append(
            f'<tr><td class="nw"><b>{esc(c["cve"])}</b></td><td class="nw">{_sev_pill(c.get("priority", "P4"))}</td>'
            f'<td>{esc(c["title"])}</td><td>{_sev_pill(c["severity"])}</td><td class="nw">{cvss}</td>'
            f'<td class="nw">{kev}</td><td class="nw">{epss}</td><td class="nw">{esc(_xpl_txt(c))}</td>'
            f'<td class="nw">{esc(c.get("confidence", "—"))}</td><td class="nw">{esc(", ".join(c["hosts"]))}</td>'
            f'<td class="nw">{esc(", ".join(str(p) for p in c["ports"]))}</td><td>{esc(", ".join(c["services"]))}</td>{extra}</tr>')
    return "".join(rows)

def generate_report(hosts, findings, exploits, metas, out_root: Path, title="Nmapilizer Report", opts=None):
    opts = opts or {}
    global REPORT_TOP_BANNER
    top_bits = []
    if opts.get("classification"): top_bits.append(f"<b>{esc(opts['classification'])}</b>")
    if opts.get("company"): top_bits.append(esc(opts["company"]))
    if opts.get("author"): top_bits.append("Prepared by " + esc(opts["author"]))
    REPORT_TOP_BANNER = ("<div style='background:#7a1f22;color:#fff;text-align:center;padding:7px;font-weight:700;letter-spacing:.04em'>"
                         + " · ".join(top_bits) + "</div>") if top_bits else ""
    ds = build_dataset(hosts, findings, exploits, metas)
    (out_root / "assets").mkdir(parents=True, exist_ok=True)
    (out_root / "assets" / "style.css").write_text(CSS + (opts.get("theme_override") or theme_css(opts.get("theme", "dark"), opts.get("accent", ""))), encoding="utf-8")
    (out_root / "assets" / "app.js").write_text(JS, encoding="utf-8")
    (out_root / "data.json").write_text(json.dumps(ds, indent=2), encoding="utf-8")
    t = ds["totals"]
    # ---- CSVs
    def write_csv(name, rows, fields):
        with open(out_root / name, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore"); w.writeheader()
            for r in rows: w.writerow(r)
    write_csv("hosts.csv", ds["hosts"], ["ip", "hostname", "status", "os", "mac", "risk_score", "risk_level"])
    write_csv("ports.csv",
              [{"ip": h["ip"], "hostname": h["hostname"], **p} for h in ds["hosts"] for p in h["ports"]],
              ["ip", "hostname", "protocol", "port", "state", "service", "product", "version", "extrainfo", "banner"])
    write_csv("findings.csv", ds["findings"],
              ["host", "hostname", "port", "protocol", "service", "banner", "severity", "category", "title", "detail", "cve", "reference", "remediation", "priority", "confidence"])
    write_csv("exploits.csv", ds["exploits"],
              ["host", "port", "service", "title", "severity", "cve", "source", "reference", "detail", "priority", "confidence"])
    # ---- index.html (executive dashboard)
    top_hosts = sorted(ds["hosts"], key=lambda h: -h["risk_score"])[:10]
    top_rows = "".join(
        f'<tr><td><a href="host_{slug_ip(h["ip"])}.html"><code>{esc(h["ip"])}</code></a></td>'
        f'<td>{esc(h["hostname"])}</td><td>{esc(h["os"] or "—")}</td>'
        f'<td>{_score_bar(h["risk_score"])}</td><td>{_sev_pill(h["risk_level"])}</td></tr>' for h in top_hosts)
    top_find = "".join(
        f'<div class="finding {esc(f.severity)}"><b>{_sev_pill(f.severity)} '
        f'<a href="host_{slug_ip(f.host)}.html">{esc(f.host)}</a>:{f.port} — {esc(f.title)}</b>'
        f'<div class="mut small">{esc(f.category)} · {esc(f.service)} {esc(f.banner)}</div>'
        f'<div>{esc(f.detail[:320])}</div></div>' for f in findings[:15])
    svc_counter = Counter(p["service"] or "unknown" for h in ds["hosts"] for p in h["ports"] if str(p["state"]).startswith("open"))
    svc_rows = "".join(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in svc_counter.most_common(20))
    sev_cards = "".join(f'<div class="card"><b style="color:var(--{SEV_VAR[s]})">{t["by_severity"][s]}</b><span>{s} findings</span></div>' for s in SEVERITIES)
    body = f"""
<div class="cards">
 <div class="card"><b>{t['hosts']}</b><span>Hosts ({t['hosts_up']} up)</span></div>
 <div class="card"><b>{t['open_ports']}</b><span>Open ports</span></div>
 <div class="card"><b>{t['flagged_hosts']}</b><span>Flagged hosts</span></div>
 <div class="card"><b>{t['findings']}</b><span>Findings</span></div>
 <div class="card"><b>{t['exploits']}</b><span>Exploit / CVE matches</span></div>
</div><div class="cards">{sev_cards}</div>
<p class="mut">Generated {esc(ds['generated'])} · Sources: {esc(', '.join(m.get('source','') for m in metas) or '—')} ·
Full detail: <a href="findings.html">Findings</a> · <a href="exploits.html">Exploits</a> · <a href="data.json">data.json</a></p>
<h2>Top risky hosts — review these first</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Risk</th><th>Level</th></tr></thead><tbody>{top_rows}</tbody></table>
<div class="grid2"><div><h2>Most common services</h2><table><thead><tr><th>Service</th><th>Count</th></tr></thead><tbody>{svc_rows}</tbody></table></div>
<div><h2>How to use this report</h2><p>1. Work <b>Findings</b> top-down (Critical → High). Each flag says <i>why</i> it matters and <i>how to fix it</i>.</p>
<p>2. Cross-check <b>Exploits</b> — a match means a public exploit/CVE exists for that banner; verify the exact patch level manually.</p>
<p>3. Open any host page for every port, banner, CPE and full NSE script output.</p></div></div>
<h2>Highest-severity findings</h2>{top_find or '<p class="mut">No findings — nothing was flagged.</p>'}"""
    (out_root / "index.html").write_text(_page("Executive dashboard", "index.html", body, title), encoding="utf-8")
    # ---- hosts.html
    rows = "".join(
        f'<tr><td><a href="host_{slug_ip(h["ip"])}.html"><code>{esc(h["ip"])}</code></a></td><td>{esc(h["hostname"])}</td>'
        f'<td>{esc(h["status"])}</td><td>{esc(h["os"] or "—")}</td><td>{len([p for p in h["ports"] if str(p["state"]).startswith("open")])}</td>'
        f'<td>{_score_bar(h["risk_score"])}</td><td>{_sev_pill(h["risk_level"])}</td></tr>'
        for h in sorted(ds["hosts"], key=(lambda x: x["ip"]) if opts.get("sort_hosts")=="ip"
                        else (lambda x: x["hostname"].lower()) if opts.get("sort_hosts")=="hostname"
                        else (lambda x: -len(x["ports"])) if opts.get("sort_hosts")=="ports"
                        else (lambda x: -x["risk_score"])))
    body = f"""<div class="tools"><input type="search" id="q" placeholder="Search IP, hostname, OS…" oninput="filterTable('q','tbl')">
<span class="mut">{len(ds['hosts'])} hosts · click a header to sort</span></div>
<table id="tbl"><thead><tr><th>IP</th><th>Hostname</th><th>Status</th><th>OS</th><th>Open ports</th><th>Risk</th><th>Level</th></tr></thead><tbody>{rows}</tbody></table>"""
    (out_root / "hosts.html").write_text(_page("All hosts, risk-ranked", "hosts.html", body, title), encoding="utf-8")
    # ---- ports.html
    prows = ""
    show_closed = bool(opts.get("show_closed"))
    for h in ds["hosts"]:
        for p in h["ports"]:
            if not show_closed and not str(p["state"]).startswith("open"): continue
            prows += (f'<tr><td><a href="host_{slug_ip(h["ip"])}.html"><code>{esc(h["ip"])}</code></a></td>'
                      f'<td>{p["port"]}/{esc(p["protocol"])}</td><td>{esc(p["service"])}</td>'
                      f'<td><code>{esc(p["banner"] or "—")}</code></td><td>{esc(",".join(p["cpes"]) or "—")}</td></tr>')
    body = f"""<div class="tools"><input type="search" id="q" placeholder="Search port, service, product, version…" oninput="filterTable('q','tbl')">
<span class="mut">{t['open_ports']} open ports{" · closed/filtered included" if show_closed else ""}</span></div>
<table id="tbl"><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th><th>CPE</th></tr></thead><tbody>{prows}</tbody></table>"""
    (out_root / "ports.html").write_text(_page("All open ports", "ports.html", body, title), encoding="utf-8")
    # ---- findings.html
    fbody = """<div class="tools"><input type="search" id="q" placeholder="Search findings…" oninput="filterCards()">
<label class="mut">Severity <select id="sev" onchange="filterCards()"><option value="">All</option>""" + \
        "".join(f'<option>{s}</option>' for s in SEVERITIES) + "</select></label></div><div id='flist'>"
    for f in findings:
        fbody += (f'<div class="finding {esc(f.severity)} fcard" data-sev="{esc(f.severity)}">'
                  f'<b>{_sev_pill(f.severity)} <a href="host_{slug_ip(f.host)}.html">{esc(f.host)}</a>:{f.port}/{esc(f.protocol)} — {esc(f.title)}</b>'
                  f'<div class="mut small">{esc(f.category)} · {esc(f.service)} · <code>{esc(f.banner)}</code>'
                  + (f' · {esc(f.cve)}' if f.cve else '') + (f' · {esc(f.reference)}' if f.reference else '') + '</div>'
                  f'<div>{esc(f.detail)}</div>'
                  + (f'<div><b>Fix:</b> {esc(f.remediation)}</div>' if f.remediation else '') + '</div>')
    fbody += """</div><script>function filterCards(){const q=document.getElementById('q').value.toLowerCase();
const s=document.getElementById('sev').value;document.querySelectorAll('.fcard').forEach(el=>{
el.style.display=(el.textContent.toLowerCase().includes(q)&&(!s||el.dataset.sev===s))?'':'none';});}</script>"""
    (out_root / "findings.html").write_text(_page(f"All findings ({len(findings)}) — manual review queue", "findings.html", fbody, title), encoding="utf-8")
    # ---- exploits.html
    erows = "".join(
        f'<tr><td>{_sev_pill(e.severity)}</td><td><a href="host_{slug_ip(e.host)}.html"><code>{esc(e.host)}</code></a>:{e.port}</td>'
        f'<td>{esc(e.service)}</td><td>{esc(e.title)}</td><td>{esc(e.cve or "—")}</td><td>{esc(e.source)}</td><td>{esc(e.reference)}</td></tr>'
        for e in exploits)
    body = f"""<div class="tools"><input type="search" id="q" placeholder="Search CVE, product, host…" oninput="filterTable('q','tbl')">
<span class="mut">{len(exploits)} matches · sources: built-in DB + local Exploit-DB lookups + NSE vulners CVEs. A banner match is a lead — verify patch level before concluding exploitability.</span></div>
<table id="tbl"><thead><tr><th>Severity</th><th>Host:Port</th><th>Service</th><th>Exploit / Issue</th><th>CVE</th><th>Source</th><th>Reference</th></tr></thead><tbody>{erows or '<tr><td colspan="7" class="mut">No exploit matches.</td></tr>'}</tbody></table>"""
    (out_root / "exploits.html").write_text(_page("Exploit & CVE matches", "exploits.html", body, title), encoding="utf-8")
    # ---- guides.html (v4)
    guides = ds.get("guides", [])
    gbody = "<p class='mut'>Validation & lab-reproduction guidance matched automatically to the CVEs and risky configurations found in these scans. Authorised testing only.</p>"
    for g in guides:
        steps = "".join(f"<li>{esc(st)}</li>" for st in g["steps"])
        cmds = "".join(f"<div class='mut small'>{esc(c['label'])}</div><pre>{esc(c['cmd'])}</pre>" for c in g["commands"])
        gbody += (f'<div class="finding {esc(g["severity"])}"><b>{_sev_pill(g["severity"])} {esc(g["title"])}</b>'
                  f'<div class="mut small"><span class="nw">{esc(g["host"])}:{g["port"]}</span> · {esc(g["service"])}'
                  + (f' · {esc(g["cve"])}' if g["cve"] else '') + (f' · CVSS {g["cvss"]}' if g["cvss"] else '') + '</div>'
                  f'<div>{esc(g["summary"])}</div><div class="mut small">Tools: {esc(", ".join(g["tools"]))}</div>'
                  f'<h3>Step-by-step validation</h3><ol>{steps}</ol><h3>Example commands</h3>{cmds}'
                  f'<div><b>Remediation:</b> {esc(g["remediation"])}</div></div>')
    if not guides: gbody += '<p class="mut">No guides matched — no known CVE/risky configuration in this data set has a guide yet.</p>'
    (out_root / "guides.html").write_text(_page(f"Exploitation guides ({len(guides)})", "guides.html", gbody, title), encoding="utf-8")
    # ---- cves.html (v4)
    cves = ds.get("cves", [])
    crows = _cve_table_rows(cves, True)
    cbody = f"""<div class="tools"><input type="search" id="q" placeholder="Search CVE, name, host, service…" oninput="filterTable('q','tbl')">
<span class="mut">{len(cves)} unique CVE(s) · sorted by priority (P1 KEV · P2 exploit exists · P3 EPSS/CVSS high · P4 other) · verify on NVD · full filtering is available in the live dashboard</span></div>
<table id="tbl"><thead><tr>{CVE_HEAD}<th>Guide</th></tr></thead><tbody>{crows or '<tr><td colspan="13" class="mut">No CVEs identified.</td></tr>'}</tbody></table>"""
    (out_root / "cves.html").write_text(_page(f"CVE register ({len(cves)})", "cves.html", cbody, title), encoding="utf-8")
    # ---- per-host pages
    for h in hosts.values():
        hf = [f for f in findings if f.host == h.ip]
        hx = [e for e in exploits if e.host == h.ip]
        port_rows = ""
        _ports_iter = sorted(h.ports.values(), key=lambda x: (x.protocol, x.portid)) if opts.get("show_closed") else h.open_ports
        for p in _ports_iter:
            scripts = "".join(f"<details><summary><code>{esc(sid)}</code></summary><pre>{esc(out)}</pre></details>" for sid, out in p.scripts.items())
            port_rows += (f'<tr><td><b>{p.portid}/{esc(p.protocol)}</b></td><td>{esc(p.state)}</td><td>{esc(p.service)}</td>'
                          f'<td><code>{esc(p.banner or "—")}</code><br><span class="mut small">{esc(", ".join(p.cpes))}</span>{scripts}</td></tr>')
        host_scripts = "".join(f"<details><summary><code>{esc(sid)}</code></summary><pre>{esc(out)}</pre></details>" for sid, out in h.scripts.items())
        fhtml = "".join(f'<div class="finding {esc(f.severity)}"><b>{_sev_pill(f.severity)} {esc(f.title)}</b>'
                        f'<div class="mut small">{esc(f.category)} · port {f.port} · {esc(f.cve)}</div><div>{esc(f.detail)}</div>'
                        + (f'<div><b>Fix:</b> {esc(f.remediation)}</div>' if f.remediation else '') + '</div>' for f in hf)
        xhtml = "".join(f'<div class="finding {esc(e.severity)}"><b>{_sev_pill(e.severity)} {esc(e.title)}</b>'
                        f'<div class="mut small">{esc(e.source)} · {esc(e.cve)} · {esc(e.reference)}</div></div>' for e in hx)
        body = f"""<p><a href="hosts.html">← All hosts</a></p>
<div class="cards"><div class="card"><b>{esc(h.ip)}</b><span>IP address</span></div>
<div class="card"><b>{esc(h.display_name)}</b><span>Hostname</span></div>
<div class="card"><b>{len(h.open_ports)}</b><span>Open ports</span></div>
<div class="card"><b>{h.risk_score}/100</b><span>Risk — {esc(h.risk_level)}</span></div>
<div class="card"><b>{len(hf)}</b><span>Findings</span></div><div class="card"><b>{len(hx)}</b><span>Exploit matches</span></div></div>
<p class="mut">OS: {esc(h.os_name or 'unknown')} {esc('('+h.os_accuracy+'% accuracy)' if h.os_accuracy else '')} ·
MAC: {esc(h.mac or '—')} {esc(h.vendor)} · Status: {esc(h.status)} · Sources: {esc(', '.join(h.sources))}</p>
<h2>Open ports & banners</h2><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner / CPE / NSE output</th></tr></thead><tbody>{port_rows or '<tr><td colspan="4" class="mut">No open ports in scan data.</td></tr>'}</tbody></table>
{f'<h2>Host scripts</h2>{host_scripts}' if host_scripts else ''}
<h2>Findings for this host ({len(hf)})</h2>{fhtml or '<p class="mut">No findings — nothing flagged on this host.</p>'}
<h2>Exploit / CVE matches ({len(hx)})</h2>{xhtml or '<p class="mut">None.</p>'}"""
        (out_root / f"host_{slug_ip(h.ip)}.html").write_text(
            _page(f"Host {h.ip} — {h.display_name}", "hosts.html", body, title), encoding="utf-8")
    # ---- summary.txt
    lines = [f"NMAPILIZER SUMMARY — {ds['generated']}", "=" * 60,
             f"Hosts: {t['hosts']} ({t['hosts_up']} up) | Open ports: {t['open_ports']} | "
             f"Findings: {t['findings']} | Exploit matches: {t['exploits']} | Flagged hosts: {t['flagged_hosts']}",
             "By severity: " + ", ".join(f"{s}={t['by_severity'][s]}" for s in SEVERITIES), "",
             "TOP FINDINGS:"]
    lines += [f"[{f.severity}] {f.host}:{f.port} {f.title} ({f.category})" for f in findings[:50]]
    lines.append(f"Author: {AUTHOR_NAME}  |  " + "  ".join(f"{n}: {u}" for n, u in AUTHOR_LINKS))
    (out_root / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ds

def next_report_dir(base: Path, now=None):
    now = now or datetime.now()
    stamp = now.strftime("%d%m%Y")
    n = 1
    while True:
        cand = base / f"{stamp}_{n:03d}_Nmapilizer_Report"
        if not cand.exists(): return cand
        n += 1

# --------------------------------------------------------------------------
# LIVE WEB DASHBOARD — one page, import in the browser, instant re-render
# --------------------------------------------------------------------------
LIVE_HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="author" content="@BudSec"><title>Nmapilizer live dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap" rel="stylesheet">
<style id="themeCss">__CSS__</style><style id="themeVars"></style>
<style>
/* ===== v5 layout: full width, compact, no sideways scroll ===== */
/* ===== v5.2 padding levels: one toggle, whole app (Compact / Comfortable / Spacious) ===== */
body{--pad-page:0 12px 12px;--pad-head:6px 0 2px;--pad-bar:6px 8px;--pad-card:7px 10px;--pad-cell:5px 8px;--pad-btn:5px 10px;--pad-gap:8px}
body.pad-compact{--pad-page:0 12px 12px;--pad-head:6px 0 2px;--pad-bar:6px 8px;--pad-card:7px 10px;--pad-cell:5px 8px;--pad-btn:5px 10px;--pad-gap:8px}
body.pad-comfortable{--pad-page:0 20px 22px;--pad-head:14px 0 8px;--pad-bar:12px;--pad-card:14px 16px;--pad-cell:9px 11px;--pad-btn:8px 14px;--pad-gap:12px}
body.pad-spacious{--pad-page:0 30px 38px;--pad-head:22px 0 12px;--pad-bar:18px 20px;--pad-card:22px 24px;--pad-cell:14px 16px;--pad-btn:12px 20px;--pad-gap:18px}
.wrap{max-width:none;padding:var(--pad-page)}
header{padding:var(--pad-head);display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header h1{font-size:19px;margin:0;font-weight:800;letter-spacing:-.01em}
header p{margin:0;font-size:12px}
.topctl{margin-left:auto;display:flex;gap:8px;align-items:center}
.tools{margin:6px 0;padding:var(--pad-bar)}
.filterbar{padding:var(--pad-bar);margin:0 0 6px;gap:6px}
.filterbar label{font-size:10px}
.filterbar input,.filterbar select{padding:4px 6px;font-size:12px}
.cards{gap:var(--pad-gap);margin:6px 0}
.card{padding:var(--pad-card)}.card b{font-size:21px;font-weight:800;letter-spacing:-.01em}.card span{font-size:10.5px;font-weight:600}
td,th{padding:var(--pad-cell)}
.btn{padding:var(--pad-btn);border-radius:8px;border:1px solid var(--line);background:var(--panel2);color:var(--txt);font:inherit;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:filter .1s ease,border-color .1s ease,background .1s ease}
.btn:hover{filter:brightness(1.06);border-color:var(--acc)}
.btn.primary{background:var(--acc);border-color:var(--acc);color:var(--onacc)}
.btn.primary:hover{filter:brightness(1.08)}
.btn.danger{background:var(--danger-bg,#b3261e);border-color:var(--danger-bg,#b3261e);color:#fff}
.btn.danger:hover{background:#c9332b;border-color:#c9332b}
.btn.small{padding:3px 9px;font-size:12px;border-radius:7px}
.finding{padding:var(--pad-card)}
.setcard{padding:var(--pad-card)}
#logPanel{padding:var(--pad-bar)}
.viewhead{display:flex;align-items:center;gap:10px;margin:4px 0 6px}
.viewhead h2{margin:0;font-size:16px;display:flex;align-items:center;gap:7px}
#logSection h2{font-size:14px;margin:8px 0 4px}
#logPanel{max-height:130px}
/* ===== v5.2 main section nav: one row on the page (moved out of the side panel) ===== */
.mainnav{display:flex;gap:6px;align-items:center;margin:6px 0;padding:var(--pad-bar);background:var(--panel);border:1px solid var(--line);border-radius:12px;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:thin}
.mnavbtn{display:flex;align-items:center;gap:7px;background:transparent;border:1px solid var(--line);color:var(--fg);border-radius:9px;padding:var(--pad-btn);cursor:pointer;font:inherit;font-size:13.5px;white-space:nowrap}
.mnavbtn .ms{font-size:19px}
.mnavbtn:hover{background:var(--panel2)}
.mnavbtn.on{background:var(--acc);border-color:var(--acc);color:var(--onacc);font-weight:700}
.mnavbtn .bdg{margin-left:2px;background:var(--panel2);border:1px solid var(--line);border-radius:99px;padding:0 7px;font-size:11px;color:var(--mut)}
.mnavbtn.on .bdg{background:rgba(0,0,0,.18);color:inherit;border-color:transparent}
/* ===== v5.3 collapsible sections (host drawer + side panel groups) ===== */
.dsec{border-top:1px solid var(--line);margin-top:12px;padding-top:4px}
.dsec-head{cursor:pointer;user-select:none;display:flex;align-items:center;gap:6px}
.dsec-head:hover{color:var(--acc)}
.dsec-head .chev,.psec-head .chev{font-size:18px;color:var(--acc);flex:none}
.psec-head{cursor:pointer;user-select:none;display:flex;align-items:center;gap:4px}
.psec-head:hover{color:var(--acc)}
/* ===== v5.4 enterprise polish: surfaces, header controls, drawer ===== */
body{-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.mainnav{box-shadow:var(--shadow)}
.filterbar{box-shadow:var(--shadow)}
.topctl select{background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:5px 8px;font:inherit;font-size:13px;min-width:0;width:auto}
#drawer{box-shadow:-14px 0 44px rgba(0,0,0,.30)}
#sidePanel{box-shadow:14px 0 44px rgba(0,0,0,.30)}
.viewhead h2{font-weight:700}
.mnavbtn{transition:background .1s ease,border-color .1s ease,color .1s ease}
.mnavbtn.on{box-shadow:var(--shadow)}
#logPanel{box-shadow:var(--shadow)}
/* wrap toggle off = restore v4 strict no-wrap */
body.nowrap-all td,body.nowrap-all .prose{white-space:nowrap}
/* ===== collapsible left panel ===== */
#edgeStrip{position:fixed;left:0;top:0;bottom:0;width:26px;z-index:69;display:flex;align-items:center;justify-content:center;cursor:pointer;background:transparent}
#edgeStrip .grip{display:flex;gap:4px;opacity:0;transition:opacity .15s}
#edgeStrip .grip i{width:3px;height:34px;border-radius:2px;background:var(--acc)}
#edgeStrip:hover .grip,body.panel-open #edgeStrip .grip{opacity:1}
.btn .ms{font-size:18px;vertical-align:-4px}
.navbtn .ms{font-size:20px}
body.icon-fallback .ms{font-family:inherit;font-size:15px;vertical-align:-2px}
#sidePanel{position:fixed;left:0;top:0;bottom:0;width:252px;z-index:70;background:var(--panel);border-right:1px solid var(--line);transform:translateX(-106%);transition:transform .22s ease;box-shadow:8px 0 24px rgba(0,0,0,.35);display:flex;flex-direction:column;padding:10px}
body.panel-open #sidePanel{transform:translateX(0)}
#sidePanel h3{margin:2px 0 8px;font-size:15px;display:flex;align-items:center;gap:7px}
#sidePanel h4{margin:12px 0 5px;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.navbtn{display:flex;align-items:center;gap:9px;width:100%;text-align:left;background:transparent;border:1px solid transparent;color:var(--fg);border-radius:8px;padding:6px 8px;cursor:pointer;font:inherit;font-size:13.5px}
.navbtn:hover{background:var(--panel2)}
.navbtn.on{background:var(--panel2);border-color:var(--acc);color:var(--acc)}
.navbtn .bdg{margin-left:auto;background:var(--panel2);border:1px solid var(--line);border-radius:99px;padding:0 7px;font-size:11px;color:var(--mut)}
.navbtn.on .bdg{color:var(--acc)}
#sidePanel .spacer{flex:1}
/* ===== import modal ===== */
.overlay{position:fixed;inset:0;background:rgba(2,6,12,.72);z-index:90;display:flex;align-items:center;justify-content:center}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;width:min(560px,92vw);box-shadow:0 18px 50px rgba(0,0,0,.5)}
.modal h3{margin:0 0 4px;display:flex;align-items:center;gap:8px}
#modalDrop{border:2px dashed var(--line);border-radius:12px;padding:34px 14px;text-align:center;cursor:pointer;margin-top:10px}
#modalDrop:hover,#modalDrop.over{border-color:var(--acc);background:var(--panel2)}
#modalDrop .ms{font-size:40px;color:var(--acc)}
/* ===== graph topology ===== */
#topoOuter{position:relative;height:calc(100vh - 318px);min-height:430px;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:var(--panel2)}
#topoCanvas{position:absolute;left:0;top:0;transform-origin:0 0}
#topoSvg{position:absolute;left:0;top:0;overflow:visible;pointer-events:none}
.gnode{position:absolute;width:var(--nw,104px);margin-left:calc(var(--nw,104px)/-2);margin-top:-31px;background:var(--panel);border:1.5px solid var(--line);border-radius:10px;padding:5px 4px 4px;text-align:center;cursor:grab;user-select:none;box-shadow:0 3px 10px rgba(0,0,0,.3);touch-action:none}
.gnode:active{cursor:grabbing}
.gnode .ms{font-size:23px;line-height:1}
.gnode .ip{font:700 11px 'JetBrains Mono',monospace;white-space:nowrap}
.gnode .hn{font-size:10px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.gnode.hub{border-width:2.5px}
.gnode.core{background:var(--panel2);border-style:dashed}
.glabel{position:absolute;transform:translate(-50%,-100%);background:var(--panel);border:1px solid var(--acc);color:var(--acc);border-radius:99px;padding:1px 10px;font:700 11px 'JetBrains Mono',monospace;white-space:nowrap;pointer-events:none}
.topoBar{display:flex;gap:6px;align-items:center;margin:0 0 6px;flex-wrap:wrap}
/* settings */
.setgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px}
.setcard{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.setcard h3{margin:0 0 8px;font-size:14px;display:flex;gap:7px;align-items:center}
.setrow{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:7px 0;font-size:13px}
.setrow select,.setrow input[type=color]{background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:4px 6px}
.switch{position:relative;width:38px;height:20px;flex:none}
.switch input{opacity:0;width:0;height:0}
.switch i{position:absolute;inset:0;background:var(--panel2);border:1px solid var(--line);border-radius:99px;cursor:pointer}
.switch i:before{content:'';position:absolute;width:14px;height:14px;border-radius:50%;background:var(--mut);top:2px;left:2px;transition:.15s}
.switch input:checked + i{border-color:var(--acc)}
.switch input:checked + i:before{transform:translateX(18px);background:var(--acc)}

/* ---- v7.1: top-of-page progress bar ---- */
#topProg{position:fixed;top:0;left:0;right:0;z-index:140;transform:translateY(-110%);transition:transform .45s var(--spring,ease);background:var(--panel);border-bottom:1px solid var(--line);box-shadow:var(--shadow)}
#topProg.on{transform:none}
#topProg .track{height:4px;background:var(--panel2)}
#tpBar{height:100%;width:2%;background:linear-gradient(90deg,var(--acc),color-mix(in srgb,var(--acc) 55%,#fff));transition:width .3s var(--ease-out,ease);position:relative;overflow:hidden}
#tpBar::after{content:'';position:absolute;inset:0;background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.55) 50%,transparent 70%);animation:tpShine 1.2s linear infinite}
@keyframes tpShine{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
#topProg .row{display:flex;align-items:center;gap:10px;padding:6px 16px;font-size:13px;color:var(--txt)}
#topProg #tpTxt{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#topProg #tpPct{font-variant-numeric:tabular-nums;color:var(--acc)}
#topProg .spin{color:var(--acc);font-size:18px;animation:spinr 1s linear infinite}
@keyframes spinr{to{transform:rotate(360deg)}}
/* ===================== v6: motion system (ported from beUI motion patterns) ===================== */
:root{--spring:cubic-bezier(.34,1.56,.64,1);--ease-out:cubic-bezier(.22,1,.36,1)}
option,optgroup{background:var(--panel);color:var(--txt)}
::placeholder{color:var(--mut);opacity:.85}
.filterbar input,.filterbar select,.setrow select,.setrow input[type=color],.topctl select{color:var(--txt);background:var(--panel2)}
.filterbar label,.mut{color:var(--mut)}
.mnavbtn,.navbtn{color:var(--txt)}
.mnavbtn .bdg,.navbtn .bdg{color:var(--mut)}
#logPanel{background:var(--codebg);color:var(--txt)}
/* --- Button: spring press + Magnetic hover --- */
.btn,.mnavbtn,.navbtn{transition:transform .35s var(--spring),background .18s,border-color .18s,color .18s,filter .18s}
.btn:active,.mnavbtn:active,.navbtn:active{transform:scale(.95);transition-duration:.08s}
.btn.primary{will-change:transform}
/* --- Tabs: spring gliding indicator + Shared-layout hover pill --- */
.mainnav{position:relative}
.mainnav .tabind,.mainnav .hoverpill{position:absolute;top:0;left:0;height:0;width:0;border-radius:9px;pointer-events:none;z-index:0}
.mainnav .tabind{background:var(--acc);box-shadow:var(--shadow);transition:transform .5s var(--spring),width .5s var(--spring),height .3s,opacity .2s}
.mainnav .hoverpill{background:var(--panel2);opacity:0;transition:transform .32s var(--ease-out),width .32s var(--ease-out),height .2s,opacity .2s;filter:blur(0)}
.mainnav .hoverpill.show{opacity:1}
.mnavbtn{position:relative;z-index:1;background:transparent!important}
.mnavbtn.on{color:var(--onacc)!important;background:transparent!important;box-shadow:none;border-color:transparent}
.mnavbtn:hover:not(.on){border-color:var(--acc)}
.mnavbtn.on .bdg{background:rgba(0,0,0,.22);color:inherit}
/* --- left side-menu line (hover to open) + Animated Sidebar / Drawer --- */
#edgeStrip{width:20px;z-index:69}
#edgeStrip .line{position:absolute;left:0;top:50%;height:46vh;width:4px;margin-top:-23vh;border-radius:0 6px 6px 0;background:linear-gradient(180deg,transparent,var(--acc) 22%,var(--acc) 78%,transparent);opacity:.85;transition:width .3s var(--spring),opacity .2s,box-shadow .3s;animation:linePulse 3.2s ease-in-out infinite}
#edgeStrip:hover .line,body.panel-open #edgeStrip .line{width:7px;opacity:1;animation:none;box-shadow:0 0 18px var(--acc)}
@keyframes linePulse{0%,100%{opacity:.45;box-shadow:0 0 0 transparent}50%{opacity:.95;box-shadow:0 0 14px var(--acc)}}
#edgeStrip .grip{display:none}
#panelScrim{position:fixed;inset:0;z-index:68;background:rgba(2,6,12,.28);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);opacity:0;pointer-events:none;transition:opacity .25s}
body.panel-open #panelScrim{opacity:1}
body.panel-pinned #panelScrim{pointer-events:auto}
#sidePanel{width:276px;overflow-y:auto;transform:translateX(-108%);transition:transform .55s var(--spring),box-shadow .3s;will-change:transform}
body.panel-open #sidePanel{transform:translateX(0)}
#sidePanel>*{position:relative;z-index:1}
#sidePanel .glide{position:absolute;left:8px;right:8px;top:0;height:0;border-radius:8px;background:var(--panel2);border:1px solid var(--line);z-index:0;opacity:0;transition:transform .3s var(--ease-out),height .2s,opacity .2s;pointer-events:none}
#sidePanel .glide.show{opacity:1}
#sidePanel .navbtn:hover{background:transparent}
body.panel-open #sidePanel .navbtn,body.panel-open #sidePanel h4,body.panel-open #sidePanel .authorcard{animation:itemIn .5s var(--ease-out) both;animation-delay:calc(var(--i,0)*38ms + 90ms)}
@keyframes itemIn{from{opacity:0;transform:translateX(-18px);filter:blur(4px)}to{opacity:1;transform:none;filter:none}}
.psec-body{overflow:hidden}
.psec-body.anim,.dsec-body.anim{transition:height .42s var(--spring),opacity .25s}
.chev{transition:transform .35s var(--spring);display:inline-block}
/* --- Cards: count-up numbers + Tilt Card with glare --- */
.cards{perspective:900px}
.card{position:relative;overflow:hidden;transform-style:preserve-3d;transition:transform .35s var(--ease-out),box-shadow .25s,border-color .2s;will-change:transform}
.card::after{content:'';position:absolute;inset:0;pointer-events:none;opacity:0;transition:opacity .25s;background:radial-gradient(160px circle at var(--mx,50%) var(--my,50%),color-mix(in srgb,var(--acc) 26%,transparent),transparent 70%)}
.card:hover{border-color:var(--acc)}
.card:hover::after{opacity:1}
.card b{font-variant-numeric:tabular-nums;color:var(--txt)}
.cards.enter .card{animation:cardIn .55s var(--spring) both;animation-delay:calc(var(--i,0)*45ms)}
@keyframes cardIn{from{opacity:0;transform:translateY(14px) scale(.94)}to{opacity:1;transform:none}}
/* --- view transitions: blur-fade + stagger --- */
#view.enter{animation:viewIn .42s var(--ease-out) both}
#view.enter tbody tr,#view.enter .finding,#view.enter .setcard{animation:rowIn .5s var(--ease-out) both;animation-delay:calc(var(--i,0)*22ms)}
@keyframes viewIn{from{opacity:0;filter:blur(6px);transform:translateY(8px)}to{opacity:1;filter:none;transform:none}}
@keyframes rowIn{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:none}}
/* --- Center-morph modals + spring drawer --- */
.overlay{backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);animation:fadeIn .25s both}
.overlay .modal{animation:morphIn .5s var(--ease-out) both}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes morphIn{from{clip-path:inset(50% 50% 50% 50% round 14px);opacity:.3;transform:scale(.96)}to{clip-path:inset(0 0 0 0 round 14px);opacity:1;transform:none}}
#drawerWrap{backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);animation:fadeIn .25s both}
#drawerWrap #drawer{animation:drawerIn .55s var(--spring) both}
@keyframes drawerIn{from{transform:translateX(100%)}to{transform:none}}
/* --- Theme Toggle: circle clip-path reveal (View Transition API) --- */
::view-transition-old(root),::view-transition-new(root){animation:none;mix-blend-mode:normal}
::view-transition-old(root){z-index:1}::view-transition-new(root){z-index:2}
/* --- header: Text Animation shimmer + author chip --- */
header h1 .shimmer{font-weight:800}
.hdrAuthor{display:inline-flex;align-items:center;gap:6px;padding:3px 8px 3px 10px;border:1px solid var(--line);border-radius:99px;background:var(--panel);font-size:12px;color:var(--mut)}
.hdrAuthor b{color:var(--txt)}
.hdrAuthor a.soc{width:22px;height:22px}.hdrAuthor a.soc svg{width:11px;height:11px}
#sidePanel .authorcard{margin-top:10px;background:var(--panel2)}
footer{text-align:center}
@media(max-width:760px){.hdrAuthor{display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}#edgeStrip .line{animation:none}}

@media print{#topProg,#panelScrim,#sidePanel,#edgeStrip,.topctl,.tools,.filterbar,.viewhead .btn,#logSection,.mainnav,#padBtn{display:none!important}}
</style></head>
<body>
<div id="topProg" role="status" aria-live="polite"><div class="track"><div id="tpBar"></div></div><div class="row"><span class="ms spin">progress_activity</span><span id="tpTxt">Working…</span><b id="tpPct">0%</b></div></div>
<div id="panelScrim"></div>
<div id="edgeStrip" title="Hover to open the menu — click to pin it" aria-label="Open side menu" role="button" tabindex="0"><span class="line"></span></div>
<aside id="sidePanel">
  <h3><span class="ms" style="color:var(--acc)">radar</span> Nmapilizer <span class="mut small">v__VERSION__</span>
  <button class="btn small" style="margin-left:auto" onclick="togglePanel(false)"><span class="ms">close</span></button></h3>
  <h4 class="psec-head" data-key="p-save" onclick="toggleCol(this)"><span class="ms chev">expand_more</span> Save &amp; export</h4>
  <div class="psec-body">
  <button class="navbtn" onclick="saveFolder()"><span class="ms">save</span> Save to report folder</button>
  <button class="navbtn" onclick="dl('html')"><span class="ms">download</span> HTML file</button>
  <button class="navbtn" onclick="exportPDF()"><span class="ms">picture_as_pdf</span> PDF</button>
  <button class="navbtn" onclick="dl('csv','findings')"><span class="ms">description</span> Findings CSV</button>
  <button class="navbtn" onclick="dl('csv','exploits')"><span class="ms">description</span> Exploits CSV</button>
  <button class="navbtn" onclick="dl('json')"><span class="ms">data_object</span> Export JSON</button>
  <button class="navbtn" onclick="clearAll()"><span class="ms">delete_sweep</span> Clear all data</button>
  <span id="saveMsg" class="mut small" style="padding:4px 8px"></span>
  </div>
  <h4 class="psec-head" data-key="p-actions" onclick="toggleCol(this)"><span class="ms chev">expand_more</span> Actions</h4>
  <div class="psec-body">
  <button class="navbtn" onclick="openImport()"><span class="ms">upload_file</span> Import scans</button>
  <button class="navbtn" onclick="showHelp()"><span class="ms">help</span> Help — how to manage</button>
  <button class="navbtn" onclick="startTerminate()"><span class="ms" style="color:var(--danger)">power_settings_new</span> <span style="color:var(--danger)">Terminate tool</span></button>
  </div>
  <div class="spacer"></div>
  __AUTHOR_CARD__
  <div class="mut small" style="margin-top:10px">Sections (Hosts, Findings, Exploits, CVEs, Guides, Topology, Ports, Settings) are in the row under the header. This menu holds Save &amp; export — just hover the glowing line on the far-left edge (click it to pin).</div>
</aside>
<div class="wrap">
<header>
  <h1><span class="ms" style="color:var(--acc);vertical-align:-5px">radar</span> <span class="shimmer">Nmapilizer</span></h1>
  <p class="mut">live dashboard v__VERSION__ · Import Nmap files (.xml/.nmap/.gnmap) — analysis, graph topology, CVEs and exploit guides update instantly.</p>
  <div class="topctl">
    <span class="hdrAuthor">by __AUTHOR_COMPACT__</span>
    <button class="btn primary" onclick="openImport()"><span class="ms">upload_file</span> Import scans</button>
    <button class="btn" id="padBtn" onclick="cyclePadding()" title="Toggle padding for the whole app: Compact → Comfortable → Spacious"><span class="ms">density_medium</span> <span id="padBtnLabel">Padding: Compact</span></button>
    <label class="mut small">Theme <select id="themeSel" onchange="setSetting('theme',this.value)">
      <option value="midnight">Midnight</option><option value="dark">Dark</option><option value="light">Light</option>
      <option value="forest">Forest</option><option value="solar">Solar</option></select></label>
  </div>
</header>

<div class="mainnav" id="mainNav"></div>

<div class="filterbar" id="filterbar">
  <label>Search<input id="fSearch" type="search" size="20" placeholder="IP, host, service, banner, CVE…"></label>
  <label>Severity<select id="fSev"><option value="">All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></label>
  <label>Subnet<select id="fSubnet"><option value="">All subnets</option></select></label>
  <label>Service<select id="fService"><option value="">All services</option></select></label>
  <label>OS<select id="fOS"><option value="">All OS</option></select></label>
  <label>Device<select id="fDevice"><option value="">All devices</option></select></label>
  <label>Port<input id="fPort" type="text" size="5" placeholder="any"></label>
  <label>CVE<input id="fCVE" type="text" size="11" placeholder="CVE-…"></label>
  <label>Min risk<select id="fRisk"><option value="0">0+</option><option>25</option><option>50</option><option>70</option><option>90</option></select></label>
  <button class="btn small" onclick="clearFilters()"><span class="ms">filter_alt_off</span> Clear filters</button>
  <span class="mut small" id="filterStatus"></span>
</div>

<div class="cards" id="cards"></div>

<div class="viewhead"><h2 id="viewTitle"></h2><span class="mut small" id="meta"></span><span style="flex:1"></span><span class="mut small">Save &amp; export live in the side menu — hover the glowing line on the far-left edge.</span></div>
<div id="view"><p class="mut">Loading…</p></div>

<div id="logSection"><h2><span class="ms" style="vertical-align:-5px">terminal</span> Application activity</h2>
<div id="logPanel"></div></div>

<footer>Nmapilizer __VERSION__ · Passive analysis only — this page never scans. Verify Critical/High manually. Use only on networks you own or are authorised to assess.<br>Author: __AUTHOR_COMPACT__</footer>
</div>

<div id="drawerWrap" style="display:none;position:fixed;inset:0;background:rgba(2,6,12,.55);z-index:80" onclick="if(event.target===this)closeDrawer()">
 <div id="drawer" style="position:absolute;top:0;right:0;bottom:0;width:min(480px,94vw);background:var(--panel);border-left:1px solid var(--line);overflow:auto;padding:16px"></div>
</div>

<div id="importModal" class="overlay" style="display:none" onclick="if(event.target===this)closeImport()">
 <div class="modal">
  <h3><span class="ms" style="color:var(--acc)">upload_file</span> Import scan results
  <button class="btn small" style="margin-left:auto" onclick="closeImport()"><span class="ms">close</span></button></h3>
  <p class="mut small" style="margin:0">Nmap output files: <b>.xml</b>, <b>.nmap</b> (normal), <b>.gnmap</b> (grepable). Files are parsed on this machine and merged — duplicates are de-duplicated.</p>
  <div id="modalDrop"><span class="ms">cloud_upload</span><div><b>Drag &amp; drop files here</b></div><div class="mut small">or click to browse — multiple files at once is fine</div></div>
  <input type="file" id="fileInput" accept=".xml,.nmap,.gnmap" multiple hidden>
  <div id="importMsg" class="mut small" style="margin-top:8px"></div>
 </div>
</div>

<div id="helpModal" class="overlay" style="display:none" onclick="if(event.target===this)closeHelp()">
 <div class="modal">
  <h3><span class="ms" style="color:var(--acc)">help</span> Welcome to Nmapilizer — how to manage this app</h3>
  <p class="mut small" style="margin:2px 0 10px">Sections are the <b>row of buttons under the header</b>; saving lives in the <b>side panel</b>. Quick tour:</p>
  <div style="display:grid;gap:9px;font-size:13.5px">
   <div style="display:flex;gap:10px;align-items:center"><span class="ms" style="color:var(--acc)">dashboard</span><span><b>Sections:</b> Hosts, Findings, Exploits, CVEs, Exploit Guides, Topology, Ports and Settings are the row right under the header — click one to switch. The counts on each button update live.</span></div>
   <div style="display:flex;gap:10px;align-items:center"><span style="display:flex"><i style="width:5px;height:30px;border-radius:0 4px 4px 0;background:var(--acc);display:block;box-shadow:0 0 10px var(--acc)"></i></span><span><b>Save &amp; export menu:</b> move your mouse onto the glowing line on the far-left edge — the menu slides open. <b>Click the line</b> to pin it open with Save to report folder, HTML, PDF, Findings/Exploits CSV, Export JSON — and Terminate.</span></div>
   <div style="display:flex;gap:10px;align-items:center"><span class="ms" style="color:var(--acc)">upload_file</span><span><b>Import scans:</b> the “Import scans” button (top right) opens a popup — drag &amp; drop your .xml / .nmap / .gnmap files there.</span></div>
   <div style="display:flex;gap:10px;align-items:center"><span class="ms" style="color:var(--acc)">density_medium</span><span><b>Padding:</b> the “Padding” button (top right) cycles the spacing of the whole app: Compact → Comfortable → Spacious.</span></div>
   <div style="display:flex;gap:10px;align-items:center"><span class="ms" style="color:var(--acc)">settings</span><span><b>Make it yours:</b> Settings (last button in the row) controls theme, colours, padding, the graph layout and more. The Theme menu at the top right recolours the whole app instantly.</span></div>
  </div>
  <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
   <button class="btn" onclick="closeHelp()">Got it — start using</button>
   <button class="btn primary" onclick="manageFromHelp()"><span class="ms">dashboard</span> Manage Nmapilizer — click here</button>
  </div>
  <div class="mut small" style="margin-top:8px">You can reopen this any time from the panel: <b>Help — how to manage</b>.</div>
 </div>
</div>

<div id="termOverlay" class="overlay" style="display:none">
 <div class="modal" style="border-color:var(--danger)">
  <h3 style="color:var(--danger)"><span class="ms">power_settings_new</span> Terminate Nmapilizer?</h3>
  <div id="termBody"></div>
 </div>
</div>
<script>
const $=id=>document.getElementById(id);
const NL=String.fromCharCode(10);
const _reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEVS=['Critical','High','Medium','Low','Info'];
const THEMES={
 midnight:{bg:'#070a1a',panel:'#0d1129',panel2:'#141a3d',fg:'#e7eaf6',mut:'#8f97c0',line:'#232a52',acc:'#5ee1a0',hover:'#1b2150',codebg:'#0a0d24',codefg:'#ffd479',onacc:'#052e16',shadow:'0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)',danger:'#ff8080',crit:'#ff6369',high:'#ff9f43',med:'#ffc53d',low:'#5bd17a',info:'#9fb0c4'},
 dark:{bg:'#0b0e13',panel:'#12161d',panel2:'#171c25',fg:'#e6e9ee',mut:'#8b94a3',line:'#232a35',acc:'#4da3ff',hover:'#1a2230',codebg:'#0a0d12',codefg:'#ffd479',onacc:'#04182e',shadow:'0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28)',danger:'#ff8080',crit:'#ff6369',high:'#ff9f43',med:'#ffc53d',low:'#5bd17a',info:'#9fb0c4'},
 light:{bg:'#edf1f7',panel:'#ffffff',panel2:'#e6ecf4',fg:'#132033',mut:'#52677e',line:'#ccd6e4',acc:'#0b6bcb',hover:'#e8f0fb',codebg:'#edf2f8',codefg:'#0b5394',onacc:'#ffffff',shadow:'0 1px 2px rgba(16,42,80,.08),0 6px 18px rgba(16,42,80,.07)',danger:'#b3261e',crit:'#c62828',high:'#b84a05',med:'#8a5a00',low:'#1a7f37',info:'#52677e'},
 forest:{bg:'#0a140d',panel:'#0f1f14',panel2:'#14301c',fg:'#e4f2e6',mut:'#8fb598',line:'#1f4630',acc:'#7be495',hover:'#173826',codebg:'#0a1810',codefg:'#ffd479',onacc:'#07280f',shadow:'0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28)',danger:'#ff8080',crit:'#ff6369',high:'#ff9f43',med:'#ffc53d',low:'#5bd17a',info:'#9fb0c4'},
 solar:{bg:'#171106',panel:'#221a0c',panel2:'#2e2210',fg:'#f7ecd4',mut:'#c2a878',line:'#4a3a1c',acc:'#ffb020',hover:'#3a2a12',codebg:'#1d1508',codefg:'#ffd479',onacc:'#2a1a00',shadow:'0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28)',danger:'#ff8080',crit:'#ff6369',high:'#ff9f43',med:'#ffc53d',low:'#5bd17a',info:'#9fb0c4'}};
function onAccent(hex){const m=/^#?([0-9a-f]{6})$/i.exec(hex||'');if(!m)return '#ffffff';const n=parseInt(m[1],16),c=[n>>16&255,n>>8&255,n&255].map(v=>{v/=255;return v<=.03928?v/12.92:Math.pow((v+.055)/1.055,2.4);});const L=.2126*c[0]+.7152*c[1]+.0722*c[2];return L>.35?'#0b1220':'#ffffff';}
function applyTheme(name){const t=THEMES[name]||THEMES.midnight;let css=':root{';for(const k in t)css+='--'+k+':'+t[k]+';';css+='--txt:'+t.fg+';--code:'+t.codebg+';color-scheme:'+(name==='light'?'light':'dark')+';';$('themeVars').textContent=css+'}';}
/* ---------- settings (persisted in this browser) ---------- */
const SKEY='nmapilizer5-settings';
let SETTINGS={theme:'midnight',accent:'',padding:'compact',landing:'hosts',showLog:true,autoRefresh:true,wrapText:true,termSteps:3,topoLayout:'star',nodeSize:'M',subnetLabels:true};
try{const saved=JSON.parse(localStorage.getItem(SKEY)||'null');if(saved){SETTINGS=Object.assign(SETTINGS,saved);if(saved.density&&!saved.padding)SETTINGS.padding=(saved.density==='comfortable'?'comfortable':'compact');}}catch(e){}
function persistSettings(){try{localStorage.setItem(SKEY,JSON.stringify(SETTINGS));}catch(e){}}
function _setSettingCore(key,val){SETTINGS[key]=val;persistSettings();applySettings();if(key==='topoLayout'||key==='nodeSize'||key==='subnetLabels'){topoSig='';}if(TAB==='settings'&&key!=='theme')render();if(key==='theme')logLine('Theme changed to '+val);}
function setSetting(key,val){
 if(key==='theme'&&document.startViewTransition&&!_reduce){const el=$('themeSel'),r=el.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2,R=Math.hypot(Math.max(x,innerWidth-x),Math.max(y,innerHeight-y));
  const vt=document.startViewTransition(()=>{_setSettingCore(key,val);});
  vt.ready.then(()=>{document.documentElement.animate({clipPath:['circle(0px at '+x+'px '+y+'px)','circle('+R+'px at '+x+'px '+y+'px)']},{duration:650,easing:'cubic-bezier(.22,1,.36,1)',pseudoElement:'::view-transition-new(root)'});}).catch(()=>{});
  vt.finished.then(()=>updateTabInd()).catch(()=>{});return;}
 _setSettingCore(key,val);}
function syncTheme(){try{const cs=getComputedStyle(document.documentElement),v={};['bg','panel','panel2','line','txt','mut','acc','hover','codebg','codefg','onacc','shadow','crit','high','med','low','info','danger'].forEach(k=>{v[k]=cs.getPropertyValue('--'+k).trim();});fetch('/api/theme',{method:'POST',body:JSON.stringify({vars:v,scheme:SETTINGS.theme==='light'?'light':'dark'})}).catch(()=>{});}catch(e){}}
function applySettings(){
 applyTheme(SETTINGS.theme);$('themeSel').value=SETTINGS.theme;
 if(SETTINGS.accent){document.documentElement.style.setProperty('--acc',SETTINGS.accent);document.documentElement.style.setProperty('--onacc',onAccent(SETTINGS.accent));}else{document.documentElement.style.removeProperty('--acc');document.documentElement.style.removeProperty('--onacc');}
 document.body.classList.remove('pad-compact','pad-comfortable','pad-spacious','comfortable');
 document.body.classList.add('pad-'+(SETTINGS.padding||'compact'));
 const pbl=$('padBtnLabel');if(pbl)pbl.textContent='Padding: '+padLabel();
 document.body.classList.toggle('nowrap-all',!SETTINGS.wrapText);
 syncTheme();
 $('logSection').style.display=SETTINGS.showLog?'':'none';
 const nw={S:'88px',M:'104px',L:'126px'}[SETTINGS.nodeSize]||'104px';
 document.documentElement.style.setProperty('--nw',nw);
}
/* ---------- padding toggle: 3 levels, whole app ---------- */
const PAD_LEVELS=['compact','comfortable','spacious'];
function padLabel(){const p=SETTINGS.padding||'compact';return p[0].toUpperCase()+p.slice(1);}
function cyclePadding(){const cur=PAD_LEVELS.indexOf(SETTINGS.padding||'compact');setSetting('padding',PAD_LEVELS[(cur+1)%3]);logLine('Padding level: '+(SETTINGS.padding||'compact'));}
/* ---------- data + filters ---------- */
let DATA=null,TAB=SETTINGS.landing||'hosts',lastVersion=-1,firstLoad=true;
const VIEWS={hosts:['computer','Hosts'],findings:['bug_report','Findings'],exploits:['swords','Exploits'],cves:['shield','CVEs'],guides:['menu_book','Exploit Guides'],topology:['hub','Topology graph'],ports:['settings_ethernet','Ports'],settings:['settings','Settings']};
function F(){return {q:$('fSearch').value.trim().toLowerCase(),sev:$('fSev').value,subnet:$('fSubnet').value,service:$('fService').value,os:$('fOS').value,device:$('fDevice').value,port:$('fPort').value.trim(),cve:$('fCVE').value.trim().toLowerCase(),risk:+$('fRisk').value};}
function anyFilter(f){return f.q||f.sev||f.subnet||f.service||f.os||f.device||f.port||f.cve||f.risk>0;}
function subnetOf(ip){const p=String(ip).split('.');return p.length===4?p[0]+'.'+p[1]+'.'+p[2]+'.0/24':'(other)';}
function osShort(os){if(!os)return 'Unknown';const m=String(os).match(/^(Linux|Windows|FreeBSD|OpenBSD|macOS|Cisco|Android|VMware|Ubuntu|Debian)/i);return m?m[1]:String(os).split(' ')[0];}
const DEVICES=[['Router','router',['router','gateway','mikrotik','openwrt','dd-wrt'],[749,7549]],['Switch','lan',['switch'],[]],
 ['Firewall','shield_lock',['firewall','pfsense','fortigate','fortinet','palo alto','sophos','watchguard'],[]],
 ['Printer','print',['printer','laserjet','officejet','epson','canon'],[515,631,9100]],['Camera','videocam',['camera','ipcam','hikvision','dahua','axis'],[554,8899]],
 ['Storage / NAS','storage',['nas','synology','qnap','freenas','truenas'],[5000,5001,3260,2049]],['Phone / VoIP','call',['voip','phone','sip'],[5060,5061]],
 ['Server','dns',['server','srv','dc0','dc1','mail','web','sql','db'],[3389,1433,1521,3306,5432,8080,8443]],['IoT','sensors',['iot','sensor','thermostat','smart'],[1883,5683]],['Workstation','computer',[],[]]];
function deviceOf(h){const os=(h.os||'').toLowerCase(),hn=(h.hostname||'').toLowerCase();const ports=new Set((h.ports||[]).filter(p=>p.state==='open').map(p=>+p.port));
 for(const [name,icon,keys,kports] of DEVICES){if(keys.some(k=>os.includes(k)||hn.includes(k))||kports.some(p=>ports.has(p)))return {name,icon};}
 if(/windows (10|11)|windows 7/i.test(h.os||''))return {name:'Workstation',icon:'computer'};
 if(/windows|linux|unix|bsd/i.test(h.os||''))return {name:'Server',icon:'dns'};
 return {name:'Host',icon:'devices'};}
function hostMatches(h,f){if(f.subnet&&subnetOf(h.ip)!==f.subnet)return false;if(f.os&&osShort(h.os)!==f.os)return false;
 if(f.device&&deviceOf(h).name!==f.device)return false;if(h.risk_score<f.risk)return false;
 if(f.port&&!(h.ports||[]).some(p=>String(p.port)===f.port&&p.state==='open'))return false;
 if(f.service&&!(h.ports||[]).some(p=>(p.service||'').toLowerCase()===f.service))return false;
 if(f.cve&&!(DATA.exploits.some(e=>e.host===h.ip&&(e.cve||'').toLowerCase().includes(f.cve))||DATA.findings.some(x=>x.host===h.ip&&x.title.toLowerCase().includes(f.cve))))return false;
 if(f.q){const hay=(h.ip+' '+(h.hostname||'')+' '+(h.os||'')+' '+(h.ports||[]).map(p=>p.port+' '+p.service+' '+p.product).join(' ')).toLowerCase();if(!hay.includes(f.q))return false;}
 return true;}
function findingPass(x,f,hostsByIp){const h=hostsByIp[x.host];if(f.sev&&x.severity!==f.sev)return false;
 if(h&&!hostMatches(h,Object.assign({},f,{sev:'',q:f.q&&x.title.toLowerCase().includes(f.q)?'':f.q})))return false;
 if(f.q&&!(x.title+' '+x.host+' '+x.port+' '+(x.banner||'')).toLowerCase().includes(f.q))return false;
 if(f.port&&String(x.port)!==f.port)return false;if(f.service&&(x.service||'').toLowerCase()!==f.service)return false;
 if(f.cve&&!x.title.toLowerCase().includes(f.cve))return false;return true;}
/* ---------- activity log ---------- */
let logLines=[],seenActivity=0;
function stamp(){const d=new Date();return d.toTimeString().slice(0,8);}
function logLine(msg){logLines.push('['+stamp()+'] '+msg);if(logLines.length>220)logLines=logLines.slice(-220);
 $('logPanel').textContent=logLines.join(NL);$('logPanel').scrollTop=1e7;}
function mergeServerActivity(){if(!DATA||!DATA.activity)return;while(seenActivity<DATA.activity.length){const a=DATA.activity[seenActivity++];logLines.push('['+a.time+'] '+a.msg);}if(logLines.length>220)logLines=logLines.slice(-220);$('logPanel').textContent=logLines.join(NL);$('logPanel').scrollTop=1e7;}
/* ---------- tables: hover copy ---------- */
function copyTable(btn){const tbl=btn.parentElement.querySelector('table');if(!tbl)return;
 const rows=[...tbl.querySelectorAll('tr')].map(tr=>[...tr.children].map(td=>td.textContent.trim()).join(String.fromCharCode(9)));
 navigator.clipboard.writeText(rows.join(NL)).then(()=>{btn.textContent='Copied!';logLine('Table copied to clipboard ('+rows.length+' rows)');setTimeout(()=>btn.textContent='Copy table',1500);});}
function enhanceTables(){document.querySelectorAll('#view table').forEach(t=>{if(t.parentElement.classList.contains('tblwrap'))return;
 const w=document.createElement('div');w.className='tblwrap';const b=document.createElement('button');b.className='copybtn';b.textContent='Copy table';b.onclick=()=>copyTable(b);
 t.parentNode.insertBefore(w,t);w.appendChild(b);w.appendChild(t);});}
function pill(sev){return '<span class="pill '+sev+'">'+sev+'</span>';}
/* ---------- renderers ---------- */
function topIssues(ip){const order={Critical:0,High:1,Medium:2,Low:3,Info:4};return DATA.findings.filter(x=>x.host===ip).sort((a,b)=>order[a.severity]-order[b.severity]).slice(0,3).map(x=>x.title);}
function hostsHTML(hosts){if(!hosts.length)return '<p class="mut">No hosts match the current filters.</p>';
 return '<table><thead><tr><th></th><th>IP</th><th>Hostname</th><th>Device</th><th>OS</th><th>Open ports</th><th>Risk</th><th>Top issues</th></tr></thead><tbody>'+
 hosts.map(h=>{const d=deviceOf(h);const open=(h.ports||[]).filter(p=>p.state==='open');
  return '<tr class="click" onclick="openHost(\''+h.ip+'\')"><td><span class="ms" style="color:var(--acc)">'+d.icon+'</span></td><td class="nw"><b>'+h.ip+'</b></td><td class="nw">'+esc(h.hostname||'—')+'</td><td class="nw">'+d.name+'</td><td>'+esc(h.os||'—')+'</td><td class="nw">'+open.length+' <span class="mut">'+open.slice(0,6).map(p=>p.port).join(', ')+'</span></td><td><span class="risk r'+Math.min(3,Math.floor(h.risk_score/25))+'">'+h.risk_score+'</span></td><td class="prose">'+topIssues(h.ip)+'</td></tr>';}).join('')+'</tbody></table>';}
function findingsHTML(list){if(!list.length)return '<p class="mut">No findings match the current filters.</p>';
 return '<table><thead><tr><th>Severity</th><th>Pri</th><th>Finding</th><th>Host:Port</th><th>Service</th><th>Why it matters</th></tr></thead><tbody>'+
 list.map(x=>'<tr><td class="nw">'+pill(x.severity)+'</td><td class="nw">'+(x.priority?pill(x.priority):'')+'</td><td><b>'+esc(x.title)+'</b><div class="mut small prose">'+esc(x.remediation||'')+'</div></td><td class="nw"><a href="#" onclick="openHost(\''+x.host+'\');return false">'+x.host+':'+x.port+'</a></td><td class="nw">'+esc(x.service||'')+'</td><td class="prose">'+esc(x.detail)+'</td></tr>').join('')+'</tbody></table>';}
function exploitsHTML(list){if(!list.length)return '<p class="mut">No exploit matches for the current filters.</p>';
 return '<table><thead><tr><th>Severity</th><th>Reference</th><th>Title</th><th>Host:Port</th><th>Source</th></tr></thead><tbody>'+
 list.map(e=>'<tr><td class="nw">'+pill(e.severity)+'</td><td class="nw">'+(e.cve?'<b>'+e.cve+'</b>':esc(e.reference||'—'))+'</td><td class="prose">'+esc(e.title)+'</td><td class="nw"><a href="#" onclick="openHost(\''+e.host+'\');return false">'+e.host+':'+e.port+'</a></td><td class="nw">'+esc(e.source)+'</td></tr>').join('')+'</tbody></table>';}
function xplTxt(c){const a=[];if(c.edb&&c.edb.length)a.push('EDB '+c.edb.length);if(c.msf&&c.msf.length)a.push('MSF '+c.msf.length);return a.length?a.join(' · '):'—';}
function cvesHTML(list){if(!list.length)return '<p class="mut">No CVEs match the current filters.</p>';
 const minCvss=window._cveMin||0;const rows=list.filter(c=>(c.cvss||0)>=minCvss);
 const note=DATA.intel?('Local DB: '+DATA.intel.cves.toLocaleString()+' CVEs · KEV '+DATA.intel.kev.toLocaleString()+' · updated '+(DATA.intel.updated||'n/a')):'No local DB loaded — built-in rules only';
 return '<div class="tools"><label>Min CVSS <select id="cveMinSel" onchange="window._cveMin=+this.value;render()"><option value="0">any</option><option value="4">4.0+</option><option value="7">7.0+</option><option value="9">9.0+</option></select></label><span class="mut">'+rows.length+' CVE(s) · '+note+'</span></div>'+
 '<div class="mut small" style="margin:0 0 6px"><span class="pill P1">P1</span> known exploited (KEV) · <span class="pill P2">P2</span> public exploit / Metasploit module · <span class="pill P3">P3</span> EPSS ≥10% or CVSS ≥7 · <span class="pill P4">P4</span> other — sorted by priority</div>'+
 '<table><thead><tr><th>CVE</th><th>Priority</th><th>Name</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>EPSS</th><th>Exploits</th><th>Confidence</th><th>Affected hosts</th><th>Ports</th><th>Services</th><th></th></tr></thead><tbody>'+
 rows.map(c=>'<tr><td class="nw"><b>'+c.cve+'</b></td><td class="nw">'+pill(c.priority||'P4')+'</td><td class="prose">'+esc(c.title)+'</td><td class="nw">'+pill(c.severity)+'</td><td class="nw">'+(c.cvss!=null?c.cvss:'—')+'</td><td class="nw">'+(c.kev?'<span class="pill Critical" title="'+esc(c.kev_name||'')+'">KEV</span>':'—')+'</td><td class="nw">'+(c.epss!=null?(c.epss*100).toFixed(1)+'%':'—')+'</td><td class="nw" title="'+esc((c.msf||[]).concat((c.edb||[]).map(e=>'EDB-'+e)).join(', '))+'">'+xplTxt(c)+'</td><td class="nw">'+esc(c.confidence||'—')+'</td><td class="nw">'+c.hosts.join(', ')+'</td><td class="nw">'+c.ports.join(', ')+'</td><td>'+esc(c.services.join(', '))+'</td><td class="nw">'+(c.has_guide?'<button class="btn small" onclick="gotoGuide(\''+c.cve+'\')"><span class="ms">menu_book</span> Guide</button>':'')+'</td></tr>').join('')+'</tbody></table>';}
function guideCard(g){return '<div class="finding '+g.severity+'"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+pill(g.severity)+'<b>'+esc(g.title)+'</b>'+(g.cve?'<span class="nw"><b>'+g.cve+'</b></span>':'')+(g.cvss?'<span class="mut small">CVSS '+g.cvss+'</span>':'')+'<span class="nw"><a href="#" onclick="openHost(\''+g.host+'\');return false">'+g.host+':'+g.port+'</a></span><span class="mut small">'+esc(g.service)+'</span></div>'+
 '<p class="prose">'+esc(g.summary)+'</p><div class="mut small">Tools: '+esc(g.tools.join(', '))+'</div><h3>Step-by-step validation</h3><ol>'+g.steps.map(s=>'<li class="prose">'+esc(s)+'</li>').join('')+'</ol><h3>Example commands</h3>'+
 g.commands.map(c=>'<div class="mut small">'+esc(c.label)+'</div><div class="cmdrow"><code>'+esc(c.cmd)+'</code><button class="btn small" onclick="copyCmd(this)"><span class="ms">content_copy</span></button></div>').join('')+
 '<p><b>Remediation:</b> <span class="prose">'+esc(g.remediation)+'</span></p></div>';}
function guidesHTML(list){if(!list.length)return '<p class="mut">No exploitation guides match — guides appear automatically when a known CVE or risky configuration is detected in the loaded scans.</p>';
 return '<p class="mut">Validation &amp; lab-reproduction guidance matched automatically to what was detected. Authorised testing only.</p>'+list.map(guideCard).join('');}
function copyCmd(btn){const code=btn.parentElement.querySelector('code').textContent;navigator.clipboard.writeText(code).then(()=>logLine('Command copied: '+code.slice(0,70)));}
function gotoGuide(cve){TAB='guides';window._guideFocus=cve;document.querySelectorAll('.mnavbtn[data-view]').forEach(b=>b.classList.toggle('on',b.dataset.view==='guides'));render();logLine('Jumped to exploitation guide for '+cve);}
function portsHTML(hosts){const rows=[];hosts.forEach(h=>(h.ports||[]).filter(p=>p.state==='open').forEach(p=>rows.push({h,p})));
 const f=F();const list=rows.filter(r=>(!f.port||String(r.p.port)===f.port)&&(!f.service||(r.p.service||'').toLowerCase()===f.service));
 if(!list.length)return '<p class="mut">No open ports match the current filters.</p>';
 return '<table><thead><tr><th>Host:Port</th><th>Service</th><th>Device</th><th>Banner</th></tr></thead><tbody>'+
 list.map(r=>'<tr><td class="nw"><a href="#" onclick="openHost(\''+r.h.ip+'\');return false">'+r.h.ip+':'+r.p.port+'</a></td><td class="nw">'+esc(r.p.service)+'</td><td class="nw">'+deviceOf(r.h).name+'</td><td class="prose">'+esc(r.p.product+' '+r.p.version+' '+r.p.extrainfo)+'</td></tr>').join('')+'</tbody></table>';}
/* ---------- graph topology ---------- */
let topoPos={},topoSig='',topoScale=1,topoPan={x:16,y:14},topoLinks=[],topoGroups=[];
function numIP(ip){return ip.split('.').reduce((a,n)=>a*256+(+n||0),0);}
function buildGraph(hosts){
 topoGroups=[];const bySub={};hosts.forEach(h=>{(bySub[subnetOf(h.ip)]=bySub[subnetOf(h.ip)]||[]).push(h);});
 const sig=hosts.map(h=>h.ip).sort().join(',')+'|'+SETTINGS.topoLayout;
 const relayout=sig!==topoSig;topoSig=sig;
 const subs=Object.keys(bySub).sort();let maxR=120;
 const groupInfo=subs.map(sub=>{const hs=bySub[sub].slice().sort((a,b)=>numIP(a.ip)-numIP(b.ip));
  const hub=hs.find(h=>h.ip.endsWith('.1'))||hs.find(h=>['Router','Switch','Firewall'].includes(deviceOf(h).name))||hs[0];
  const members=hs.filter(h=>h!==hub);const R=Math.max(105,members.length*17+55);if(R>maxR)maxR=R;
  return {sub,hosts:hs,hub,members,R};});
 const cell=maxR*2+190,cols=Math.max(1,Math.ceil(Math.sqrt(groupInfo.length)));
 const rows=Math.ceil(groupInfo.length/cols),worldW=cols*cell,worldH=rows*cell+(groupInfo.length>1?70:10);
 topoLinks=[];
 groupInfo.forEach((g,gi)=>{const cx=(gi%cols)*cell+cell/2,cy=Math.floor(gi/cols)*cell+cell/2+(groupInfo.length>1?60:0);
  g.cx=cx;g.cy=cy;topoGroups.push(g);
  if(relayout||!topoPos[g.hub.ip])topoPos[g.hub.ip]={x:cx,y:cy};
  g.members.forEach((h,i)=>{if(relayout||!topoPos[h.ip]){let x,y;
    if(SETTINGS.topoLayout==='grid'){const gc=Math.max(1,Math.ceil(Math.sqrt(g.members.length)));const gx=(i%gc)-(gc-1)/2,gy=Math.floor(i/gc);x=cx+gx*128;y=cy+70+gy*88;}
    else{const a=(2*Math.PI*i)/Math.max(1,g.members.length)-Math.PI/2;x=cx+Math.cos(a)*g.R;y=cy+Math.sin(a)*g.R;}
    topoPos[h.ip]={x,y};}
   topoLinks.push({a:g.hub.ip,b:h.ip,hub:true});});
  if(SETTINGS.topoLayout==='ring'&&g.members.length>1)g.members.forEach((h,i)=>topoLinks.push({a:h.ip,b:g.members[(i+1)%g.members.length].ip,hub:false}));});
 if(groupInfo.length>1){if(relayout||!topoPos.__core)topoPos.__core={x:worldW/2,y:36};
  groupInfo.forEach(g=>topoLinks.push({a:'__core',b:g.hub.ip,hub:true}));}
 return {worldW,worldH};}
function riskCol(h){if(!h)return 'var(--acc)';if(h.risk_score>=70)return 'var(--crit)';if(h.risk_score>=45)return 'var(--high)';if(h.risk_score>=20)return 'var(--med)';return 'var(--acc)';}
function topoHTML(hosts){
 if(!hosts.length)return '<p class="mut">No hosts to graph — import a scan first, or relax the filters.</p>';
 const {worldW,worldH}=buildGraph(hosts);
 let nodes='';
 if(topoGroups.length>1){const p=topoPos.__core;nodes+='<div class="gnode core" data-ip="__core" style="left:'+p.x+'px;top:'+p.y+'px"><span class="ms" style="color:var(--acc)">language</span><div class="ip">ALL NETWORKS</div><div class="hn">'+topoGroups.length+' subnet groups</div></div>';}
 topoGroups.forEach(g=>{if(SETTINGS.subnetLabels)nodes+='<div class="glabel" style="left:'+g.cx+'px;top:'+(g.cy-g.R-58)+'px">'+g.sub+' · '+g.hosts.length+' host(s)</div>';
  g.hosts.forEach(h=>{const p=topoPos[h.ip];const d=deviceOf(h);const isHub=h===g.hub;
   nodes+='<div class="gnode'+(isHub?' hub':'')+'" data-ip="'+h.ip+'" style="left:'+p.x+'px;top:'+p.y+'px;border-color:'+riskCol(h)+'"><span class="ms" style="color:'+riskCol(h)+'">'+d.icon+'</span><div class="ip">'+h.ip+'</div><div class="hn">'+esc(h.hostname||d.name)+(isHub?' · hub':'')+'</div></div>';});});
 return '<div class="topoBar"><b>'+topoGroups.length+' subnet group(s)</b><span class="mut small">Drag any node to move it · drag the background to pan · scroll to zoom · click a node for details. Hosts are linked to their subnet hub (the .1 / gateway-like device).</span><span style="flex:1"></span><button class="btn small" onclick="topoZoom(1.2)">Zoom +</button><button class="btn small" onclick="topoZoom(0.85)">Zoom −</button><button class="btn small" onclick="topoReset()">Reset layout</button></div>'+
 '<div id="topoOuter"><div id="topoCanvas"><svg id="topoSvg"></svg>'+nodes+'</div></div>';}
function drawLinks(){const svg=$('topoSvg');if(!svg)return;const maxX=Math.max(...Object.values(topoPos).map(p=>p.x),600),maxY=Math.max(...Object.values(topoPos).map(p=>p.y),400);
 svg.setAttribute('width',maxX+220);svg.setAttribute('height',maxY+160);
 svg.innerHTML=topoLinks.map(l=>{const a=topoPos[l.a],b=topoPos[l.b];if(!a||!b)return '';
  return '<line x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'" stroke="'+(l.hub?'var(--acc)':'#5b6b82')+'" stroke-width="'+(l.hub?1.7:1)+'" opacity="'+(l.hub?0.75:0.4)+'"/>';}).join('');}
function applyTopoTransform(){const c=$('topoCanvas');if(c)c.style.transform='translate('+topoPan.x+'px,'+topoPan.y+'px) scale('+topoScale+')';}
function topoZoom(f){topoScale=Math.min(2.4,Math.max(0.3,topoScale*f));applyTopoTransform();}
function topoReset(){topoSig='';topoPos={};topoScale=1;topoPan={x:16,y:14};render();logLine('Topology layout reset');}
function bindTopology(){const outer=$('topoOuter');if(!outer)return;drawLinks();applyTopoTransform();
 let drag=null;
 outer.addEventListener('pointerdown',e=>{const node=e.target.closest('.gnode');
  if(node){const ip=node.dataset.ip;drag={kind:'node',ip,sx:e.clientX,sy:e.clientY,ox:topoPos[ip].x,oy:topoPos[ip].y,moved:false};}
  else drag={kind:'pan',sx:e.clientX,sy:e.clientY,ox:topoPan.x,oy:topoPan.y,moved:false};
  outer.setPointerCapture(e.pointerId);});
 outer.addEventListener('pointermove',e=>{if(!drag)return;const dx=e.clientX-drag.sx,dy=e.clientY-drag.sy;
  if(Math.abs(dx)+Math.abs(dy)>4)drag.moved=true;
  if(drag.kind==='node'){topoPos[drag.ip]={x:drag.ox+dx/topoScale,y:drag.oy+dy/topoScale};
   const el=outer.querySelector('.gnode[data-ip="'+drag.ip+'"]');if(el){el.style.left=topoPos[drag.ip].x+'px';el.style.top=topoPos[drag.ip].y+'px';}drawLinks();}
  else{topoPan={x:drag.ox+dx,y:drag.oy+dy};applyTopoTransform();}});
 outer.addEventListener('pointerup',e=>{if(drag&&drag.kind==='node'&&!drag.moved&&drag.ip!=='__core')openHost(drag.ip);
  if(drag&&drag.kind==='node'&&drag.moved)logLine('Node moved: '+drag.ip);drag=null;});
 outer.addEventListener('wheel',e=>{e.preventDefault();topoZoom(e.deltaY<0?1.1:0.9);},{passive:false});}
/* ---------- settings view ---------- */
function sw(key){return '<label class="switch"><input type="checkbox" '+(SETTINGS[key]?'checked':'')+' onchange="setSetting(\''+key+'\',this.checked)"><i></i></label>';}
function settingsHTML(){return '<div class="setgrid">'+
 '<div class="setcard"><h3><span class="ms">palette</span> Appearance</h3>'+
 '<div class="setrow"><span>Theme</span><select onchange="setSetting(\'theme\',this.value)">'+Object.keys(THEMES).map(t=>'<option value="'+t+'"'+(SETTINGS.theme===t?' selected':'')+'>'+t[0].toUpperCase()+t.slice(1)+'</option>').join('')+'</select></div>'+
 '<div class="setrow"><span>Accent colour (blank = theme default)</span><input type="color" value="'+(SETTINGS.accent||'#4da3ff')+'" onchange="setSetting(\'accent\',this.value)"></div>'+
 '<div class="setrow"><span>Reset accent</span><button class="btn small" onclick="setSetting(\'accent\',\'\')">Theme default</button></div>'+
 '<div class="setrow"><span>Padding — whole app (same as the Padding button)</span><select onchange="setSetting(\'padding\',this.value)"><option value="compact"'+(SETTINGS.padding==='compact'?' selected':'')+'>Compact</option><option value="comfortable"'+(SETTINGS.padding==='comfortable'?' selected':'')+'>Comfortable</option><option value="spacious"'+(SETTINGS.padding==='spacious'?' selected':'')+'>Spacious</option></select></div>'+
 '<div class="setrow"><span>Wrap long sentences (recommended)</span>'+sw('wrapText')+'</div></div>'+
 '<div class="setcard"><h3><span class="ms">dashboard</span> Behaviour</h3>'+
 '<div class="setrow"><span>Default view on load</span><select onchange="setSetting(\'landing\',this.value)">'+Object.keys(VIEWS).map(v=>'<option value="'+v+'"'+(SETTINGS.landing===v?' selected':'')+'>'+VIEWS[v][1]+'</option>').join('')+'</select></div>'+
 '<div class="setrow"><span>Show activity log</span>'+sw('showLog')+'</div>'+
 '<div class="setrow"><span>Auto-refresh data (watch mode)</span>'+sw('autoRefresh')+'</div>'+
 '<div class="setrow"><span>Terminate confirmations</span><select onchange="setSetting(\'termSteps\',+this.value)"><option value="3"'+(SETTINGS.termSteps===3?' selected':'')+'>3-step (safest)</option><option value="1"'+(SETTINGS.termSteps===1?' selected':'')+'>1-step (fast)</option></select></div></div>'+
 '<div class="setcard"><h3><span class="ms">hub</span> Topology graph</h3>'+
 '<div class="setrow"><span>Link layout</span><select onchange="setSetting(\'topoLayout\',this.value)"><option value="star"'+(SETTINGS.topoLayout==='star'?' selected':'')+'>Star (hub &amp; spokes)</option><option value="ring"'+(SETTINGS.topoLayout==='ring'?' selected':'')+'>Ring + hub</option><option value="grid"'+(SETTINGS.topoLayout==='grid'?' selected':'')+'>Grid in subnet</option></select></div>'+
 '<div class="setrow"><span>Node size</span><select onchange="setSetting(\'nodeSize\',this.value)"><option value="S"'+(SETTINGS.nodeSize==='S'?' selected':'')+'>Small</option><option value="M"'+(SETTINGS.nodeSize==='M'?' selected':'')+'>Medium</option><option value="L"'+(SETTINGS.nodeSize==='L'?' selected':'')+'>Large</option></select></div>'+
 '<div class="setrow"><span>Subnet labels</span>'+sw('subnetLabels')+'</div>'+
 '<div class="setrow"><span>Reset node positions</span><button class="btn small" onclick="topoReset()">Reset layout</button></div></div>'+
 '<div class="setcard"><h3><span class="ms">restart_alt</span> Reset</h3><p class="mut small">Settings are stored in this browser only and apply instantly.</p>'+
 '<button class="btn" onclick="if(confirm(\'Reset all settings to defaults?\')){localStorage.removeItem(\''+SKEY+'\');location.reload();}">Reset all settings</button></div>'+
 '</div>';}
/* ---------- main render ---------- */
function render(){if(!DATA)return;const f=F();const hostsByIp={};DATA.hosts.forEach(h=>hostsByIp[h.ip]=h);
 const hosts=DATA.hosts.filter(h=>hostMatches(h,f));
 const findings=DATA.findings.filter(x=>findingPass(x,f,hostsByIp));
 const exploits=DATA.exploits.filter(e=>{const h=hostsByIp[e.host];const fh={host:e.host,port:e.port,severity:e.severity,title:(e.cve||'')+' '+e.title,banner:'',service:e.service||''};return findingPass(fh,f,hostsByIp);});
 const cves=DATA.cves.filter(c=>c.hosts.some(ip=>hostsByIp[ip]&&hostMatches(hostsByIp[ip],Object.assign({},f,{sev:''})))&&(!f.cve||c.cve.toLowerCase().includes(f.cve))&&(!f.sev||c.severity===f.sev));
 const guides=DATA.guides.filter(g=>hostsByIp[g.host]&&hostMatches(hostsByIp[g.host],Object.assign({},f,{sev:''}))&&(!f.sev||g.severity===f.sev)&&(!window._guideFocus||g.cve===window._guideFocus||g.guide_id===window._guideFocus));
 const subnets=new Set(DATA.hosts.map(h=>subnetOf(h.ip)));
 $('cards').innerHTML=[['computer',DATA.totals.hosts,'HOSTS'],['settings_ethernet',DATA.totals.open_ports,'OPEN PORTS'],['flag',DATA.totals.flagged_hosts,'FLAGGED HOSTS'],['bug_report',DATA.totals.findings,'FINDINGS'],['swords',DATA.totals.exploits,'EXPLOIT MATCHES'],['shield',DATA.cves.length,'UNIQUE CVES'],['menu_book',DATA.guides.length,'EXPLOIT GUIDES'],['local_fire_department',DATA.cves.filter(c=>c.kev).length,'KNOWN EXPLOITED (KEV)'],['filter_alt',hosts.length,'HOSTS AFTER FILTERS']].map((c,i)=>'<div class="card" style="--i:'+i+'"><b data-n="'+c[1]+'">'+c[1]+'</b><span>'+c[2]+'</span></div>').join('');animateCards();
 $('meta').textContent=DATA.scans.length+' file(s) loaded · generated '+DATA.generated+(DATA.intel?(' · vuln DB: '+DATA.intel.cves.toLocaleString()+' CVEs, updated '+(DATA.intel.updated||'n/a')):' · vuln DB: off');
 $('viewTitle').innerHTML='<span class="ms" style="color:var(--acc)">'+VIEWS[TAB][0]+'</span> '+VIEWS[TAB][1];
 const counts={hosts:hosts.length,findings:findings.length,exploits:exploits.length,cves:cves.length,guides:guides.length,topology:hosts.length,ports:'',settings:''};
 document.querySelectorAll('.mnavbtn[data-view]').forEach(b=>{b.classList.toggle('on',b.dataset.view===TAB);const bd=b.querySelector('.bdg');if(bd)bd.textContent=counts[b.dataset.view];});updateTabInd();
 $('filterStatus').textContent=anyFilter(f)?('Filters active — '+hosts.length+' host(s), '+findings.length+' finding(s), '+cves.length+' CVE(s)'):'';
 let html='';
 if(TAB==='hosts')html=hostsHTML(hosts);else if(TAB==='findings')html=findingsHTML(findings);
 else if(TAB==='exploits')html=exploitsHTML(exploits);else if(TAB==='cves')html=cvesHTML(cves);
 else if(TAB==='guides')html=guidesHTML(window._guideFocus?guides.concat(DATA.guides.filter(g=>g.cve===window._guideFocus&&!guides.includes(g))):guides);
 else if(TAB==='topology')html=topoHTML(hosts);else if(TAB==='ports')html=portsHTML(hosts);
 else if(TAB==='settings')html=settingsHTML();
 $('view').innerHTML=html;enhanceTables();
 if(iconFallbackOn)applyIconFallback();
 if(TAB==='topology')bindTopology();
 const sel=$('cveMinSel');if(sel)sel.value=String(window._cveMin||0);
 if(firstLoad){logLine('Scan data updated — '+DATA.totals.hosts+' hosts discovered · '+DATA.totals.findings+' findings · '+DATA.cves.length+' CVEs · '+subnets.size+' subnet group(s) identified');firstLoad=false;}
 if(window._pendingFilterLog){logLine(window._pendingFilterLog);window._pendingFilterLog=null;}}
function enterFx(){const v=$('view');if(_reduce)return;v.classList.remove('enter');void v.offsetWidth;let i=0;v.querySelectorAll('tbody tr,.finding,.setcard').forEach(el=>{el.style.setProperty('--i',Math.min(i++,24));});v.classList.add('enter');setTimeout(()=>v.classList.remove('enter'),1300);}
function showView(v){TAB=v;window._guideFocus=null;render();enterFx();togglePanel(false);}
/* Number Animation: values roll to their new count; Tilt Card: 3D tilt + cursor glare */
let _cardPrev={};
function animateCards(){const cs=$('cards');if(!cs)return;const first=!Object.keys(_cardPrev).length;if(first&&!_reduce){cs.classList.add('enter');setTimeout(()=>cs.classList.remove('enter'),1200);}
 cs.querySelectorAll('.card').forEach((card,i)=>{const b=card.querySelector('b'),to=+b.dataset.n,label=card.querySelector('span').textContent,from=(label in _cardPrev)?_cardPrev[label]:0;_cardPrev[label]=to;
  if(_reduce||!isFinite(to)||from===to){b.textContent=to;return;}const t0=performance.now(),dur=650;(function step(t){const p=Math.min(1,(t-t0)/dur),e=1-Math.pow(1-p,3);b.textContent=Math.round(from+(to-from)*e);if(p<1)requestAnimationFrame(step);else b.textContent=to;})(t0);});}
(function(){const cs=$('cards');if(!cs||_reduce)return;cs.addEventListener('mousemove',e=>{const c=e.target.closest('.card');if(!c)return;const r=c.getBoundingClientRect(),px=(e.clientX-r.left)/r.width,py=(e.clientY-r.top)/r.height;c.style.transform='perspective(700px) rotateX('+((.5-py)*10).toFixed(2)+'deg) rotateY('+((px-.5)*12).toFixed(2)+'deg) translateZ(4px)';c.style.setProperty('--mx',(px*100)+'%');c.style.setProperty('--my',(py*100)+'%');});
 cs.addEventListener('mouseout',e=>{const c=e.target.closest('.card');if(c&&!c.contains(e.relatedTarget))c.style.transform='';});})();
/* Magnetic primary buttons */
document.addEventListener('mousemove',e=>{if(_reduce)return;const b=e.target.closest&&e.target.closest('.btn.primary');document.querySelectorAll('.btn.primary.mag').forEach(x=>{if(x!==b){x.style.transform='';x.classList.remove('mag');}});if(!b)return;const r=b.getBoundingClientRect();b.classList.add('mag');b.style.transform='translate('+((e.clientX-r.left-r.width/2)*.12).toFixed(1)+'px,'+((e.clientY-r.top-r.height/2)*.18).toFixed(1)+'px)';});
/* ---------- collapsible sections (drawer + side panel) ---------- */
const COL_STATE={};
function setChev(ch,open){if(!ch)return;const n=open?'expand_more':'chevron_right';ch.textContent=(typeof iconFallbackOn!=='undefined'&&iconFallbackOn&&ICON_FB[n])?ICON_FB[n]:n;}
function toggleCol(head){const body=head.nextElementSibling;if(!body)return;const open=body.style.display==='none';
 if(!_reduce){if(open){body.style.display='';const h=body.scrollHeight;body.style.height='0px';body.style.opacity='0';body.classList.add('anim');void body.offsetHeight;body.style.height=h+'px';body.style.opacity='1';setTimeout(()=>{body.style.height='';body.style.opacity='';body.classList.remove('anim');},450);}
  else{body.style.height=body.scrollHeight+'px';body.classList.add('anim');void body.offsetHeight;body.style.height='0px';body.style.opacity='0';setTimeout(()=>{body.style.display='none';body.style.height='';body.style.opacity='';body.classList.remove('anim');},430);}}
 else body.style.display=open?'':'none';setChev(head.querySelector('.chev'),open);if(head.dataset.key)COL_STATE[head.dataset.key]=open;}
function dsec(key,title,inner){const open=COL_STATE[key]!==false;
 return '<div class="dsec"><h3 class="dsec-head" data-key="'+key+'" onclick="toggleCol(this)"><span class="ms chev">'+(open?'expand_more':'chevron_right')+'</span>'+title+'</h3><div class="dsec-body"'+(open?'':' style="display:none"')+'>'+inner+'</div></div>';}
function drawerAll(open){document.querySelectorAll('#drawer .dsec').forEach(sec=>{const head=sec.querySelector('.dsec-head'),body=sec.querySelector('.dsec-body');if(body)body.style.display=open?'':'none';setChev(head?head.querySelector('.chev'):null,open);if(head&&head.dataset.key)COL_STATE[head.dataset.key]=open;});logLine(open?'Drawer: all sections expanded':'Drawer: all sections collapsed');}
/* ---------- host drawer ---------- */
function openHost(ip){const h=(DATA?DATA.hosts:[]).find(x=>x.ip===ip);if(!h)return;const d=deviceOf(h);
 const ports=(h.ports||[]).filter(p=>p.state==='open');
 $('drawer').innerHTML='<div style="display:flex;align-items:center;gap:8px"><span class="ms" style="font-size:30px;color:var(--acc)">'+d.icon+'</span><h2 style="margin:0">'+h.ip+'</h2><span class="risk r'+Math.min(3,Math.floor(h.risk_score/25))+'">'+h.risk_score+'</span><span style="flex:1"></span><button class="btn small" onclick="closeDrawer()"><span class="ms">close</span></button></div>'+
 '<p class="mut">'+esc(h.hostname||'')+' · '+d.name+' · '+esc(h.os||'OS unknown')+'<br>MAC '+esc(h.mac||'—')+' · Vendor '+esc(h.vendor||'—')+' · Subnet <span class="nw">'+subnetOf(h.ip)+'</span></p>'+
 '<div class="mut small" style="margin:2px 0 4px">Click a section title to collapse / expand it · <a href="#" onclick="drawerAll(true);return false">Expand all</a> · <a href="#" onclick="drawerAll(false);return false">Collapse all</a></div>'+
 dsec('ports','Open ports ('+ports.length+')',(ports.map(p=>'<div class="port"><span class="nw"><b>'+h.ip+':'+p.port+'</b></span><span class="mut">'+esc(p.protocol)+' · '+esc(p.service)+'</span><span class="prose">'+esc(p.product+' '+p.version+' '+p.extrainfo)+'</span></div>').join('')||'<p class="mut">None recorded open.</p>'))+
 dsec('findings','Findings',(DATA.findings.filter(x=>x.host===ip).map(x=>'<div class="finding '+x.severity+'">'+pill(x.severity)+' <b>'+esc(x.title)+'</b><div class="mut small prose">'+esc(x.detail)+'</div></div>').join('')||'<p class="mut">No findings.</p>'))+
 dsec('exploits','Exploit matches',(DATA.exploits.filter(x=>x.host===ip).map(x=>'<div class="finding '+x.severity+'">'+pill(x.severity)+' <b>'+esc(x.cve||x.reference||'')+'</b> <span class="prose">'+esc(x.title)+'</span></div>').join('')||'<p class="mut">None.</p>'))+
 dsec('guides','Guides for this host',(DATA.guides.filter(g=>g.host===ip).map(guideCard).join('')||'<p class="mut">No guide matched this host.</p>'));
 $('drawerWrap').style.display='block';if(typeof iconFallbackOn!=='undefined'&&iconFallbackOn)applyIconFallback();logLine('Host details opened: '+ip);}
function closeDrawer(){$('drawerWrap').style.display='none';}
/* ---------- left panel ---------- */
function buildMainNav(){$('mainNav').innerHTML=Object.keys(VIEWS).map(v=>'<button class="mnavbtn" data-view="'+v+'" onclick="showView(\''+v+'\')"><span class="ms">'+VIEWS[v][0]+'</span> '+VIEWS[v][1]+'<span class="bdg"></span></button>').join('');_navFx=false;initNavFx();updateTabInd();}
let panelPinned=false;
let panelPin=false,hoverT=null,leaveT=null;
function togglePanel(open){if(!open)panelPin=false;document.body.classList.toggle('panel-open',!!open);document.body.classList.toggle('panel-pinned',!!open&&panelPin);}
function openPanelHover(){clearTimeout(leaveT);clearTimeout(hoverT);hoverT=setTimeout(()=>{document.body.classList.add('panel-open');},70);}
function closePanelHover(){clearTimeout(hoverT);if(panelPin)return;clearTimeout(leaveT);leaveT=setTimeout(()=>{if(!panelPin)togglePanel(false);},320);}
const _es=$('edgeStrip'),_sp=$('sidePanel');
_es.addEventListener('mouseenter',openPanelHover);_es.addEventListener('mouseleave',closePanelHover);
_sp.addEventListener('mouseenter',()=>{clearTimeout(leaveT);});_sp.addEventListener('mouseleave',closePanelHover);
_es.addEventListener('click',()=>{if(document.body.classList.contains('panel-open')&&panelPin){togglePanel(false);}else{panelPin=true;document.body.classList.add('panel-open','panel-pinned');}});
_es.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();_es.click();}});
$('panelScrim').addEventListener('click',()=>togglePanel(false));
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.body.classList.contains('panel-open'))togglePanel(false);});
document.addEventListener('touchstart',e=>{if(e.touches[0]&&e.touches[0].clientX<14&&!document.body.classList.contains('panel-open')){panelPin=true;document.body.classList.add('panel-open','panel-pinned');}},{passive:true});
/* stagger index for side-panel items */
(function(){let i=0;_sp.querySelectorAll('.navbtn,h4,.authorcard').forEach(el=>{el.style.setProperty('--i',i++);});})();
/* Shared-layout glide pill (side panel + section tabs) */
function attachGlide(container,sel,cls){let pill=container.querySelector('.'+cls);if(!pill){pill=document.createElement('i');pill.className=cls+(cls==='glide'?'':' ');container.insertBefore(pill,container.firstChild);}
 const move=el=>{const c=container.getBoundingClientRect(),r=el.getBoundingClientRect();const x=container===_sp?(r.left-c.left):(el.offsetLeft),y=container===_sp?(r.top-c.top+container.scrollTop):0;
  pill.style.width=(container===_sp?'':r.width+'px');pill.style.height=r.height+'px';pill.style.transform='translate('+(container===_sp?0:x)+'px,'+(container===_sp?y:el.offsetTop)+'px)';pill.classList.add('show');};
 container.addEventListener('mouseover',e=>{const el=e.target.closest(sel);if(el&&container.contains(el))move(el);});
 container.addEventListener('mouseleave',()=>pill.classList.remove('show'));}
attachGlide(_sp,'.navbtn','glide');
/* Tabs: spring layout indicator that follows the active section */
function updateTabInd(){const nav=$('mainNav');if(!nav)return;let ind=nav.querySelector('.tabind');if(!ind){ind=document.createElement('i');ind.className='tabind';nav.insertBefore(ind,nav.firstChild);}
 const on=nav.querySelector('.mnavbtn.on');if(!on){ind.style.opacity=0;return;}ind.style.opacity=1;ind.style.width=on.offsetWidth+'px';ind.style.height=on.offsetHeight+'px';ind.style.transform='translate('+on.offsetLeft+'px,'+on.offsetTop+'px)';}
let _navFx=false;function initNavFx(){const nav=$('mainNav');if(!nav||_navFx)return;_navFx=true;
 let hp=document.createElement('i');hp.className='hoverpill';nav.insertBefore(hp,nav.firstChild);
 nav.addEventListener('mouseover',e=>{const el=e.target.closest('.mnavbtn');if(!el||el.classList.contains('on')){hp.classList.remove('show');return;}hp.style.width=el.offsetWidth+'px';hp.style.height=el.offsetHeight+'px';hp.style.transform='translate('+el.offsetLeft+'px,'+el.offsetTop+'px)';hp.classList.add('show');});
 nav.addEventListener('mouseleave',()=>hp.classList.remove('show'));}
window.addEventListener('resize',()=>updateTabInd());window.addEventListener('load',()=>{updateTabInd();});
if(document.fonts&&document.fonts.ready)document.fonts.ready.then(()=>updateTabInd());
/* ---------- help popup (first load + from panel) ---------- */
function showHelp(){$('helpModal').style.display='flex';togglePanel(false);}
function closeHelp(){$('helpModal').style.display='none';try{localStorage.setItem('nmapilizer5-help-seen','1');}catch(e){}}
function manageFromHelp(){closeHelp();togglePanel(true);logLine('Help: save & export panel opened');}
/* ---------- icon font self-check + fallback symbols ---------- */
const ICON_FB={radar:'◎',menu:'☰',close:'✕',upload_file:'⬆',cloud_upload:'⬆',download:'⬇',save:'▣',picture_as_pdf:'▤',power_settings_new:'⏻',filter_alt_off:'⧩',filter_alt:'⧩',terminal:'▸',computer:'▭',dns:'▦',router:'▤',lan:'▥',shield_lock:'⛨',shield:'⛨',print:'⎙',videocam:'▣',storage:'▦',call:'☎',sensors:'◉',devices:'▭',bug_report:'✦',swords:'⚔',menu_book:'▤',hub:'✛',settings_ethernet:'≣',settings:'⚙',help:'?',flag:'⚑',language:'◍',content_copy:'⧉',restart_alt:'↺',palette:'◐',dashboard:'▦',density_medium:'☰',description:'▤',data_object:'{}',delete_sweep:'✕',expand_more:'▾',chevron_right:'▸'};
let iconFallbackOn=false;
function applyIconFallback(){document.querySelectorAll('.ms').forEach(el=>{const n=el.textContent.trim();if(ICON_FB[n])el.textContent=ICON_FB[n];});}
function iconFallbackCheck(){if(iconFallbackOn)return;const probe=document.createElement('span');probe.className='ms';probe.textContent='radar';probe.style.cssText='position:absolute;visibility:hidden;font-size:22px';document.body.appendChild(probe);const w=probe.offsetWidth;probe.remove();
 if(w>30){iconFallbackOn=true;document.body.classList.add('icon-fallback');applyIconFallback();logLine('Icon font (Google) unreachable — built-in fallback symbols active, layout unaffected');}}
/* ---------- import popup ---------- */
function openImport(){$('importModal').style.display='flex';togglePanel(false);}
function closeImport(){$('importModal').style.display='none';}
$('modalDrop').addEventListener('click',()=>$('fileInput').click());
$('fileInput').addEventListener('change',e=>{importFiles([...e.target.files]);e.target.value='';});
$('modalDrop').addEventListener('dragover',e=>{e.preventDefault();$('modalDrop').classList.add('over');});
$('modalDrop').addEventListener('dragleave',()=>$('modalDrop').classList.remove('over'));
$('modalDrop').addEventListener('drop',e=>{e.preventDefault();$('modalDrop').classList.remove('over');importFiles([...e.dataTransfer.files]);});
window.addEventListener('dragenter',e=>{if(e.dataTransfer&&[...e.dataTransfer.types].includes('Files'))openImport();});
window.addEventListener('dragover',e=>e.preventDefault());
let _imp=null,_progShown=false,_impT0=0;
function topProg(show,pct,text){const b=$('topProg');if(!b)return;b.classList.toggle('on',!!show);if(show){$('tpBar').style.width=Math.max(2,Math.min(100,pct))+'%';$('tpTxt').textContent=text;$('tpPct').textContent=Math.round(pct)+'%';}}
async function pollProgress(){
 try{const r=await fetch('/api/progress');const p=await r.json();
  if(_imp){const el=Math.round((Date.now()-_impT0)/1000);let pct,txt;
   if(_imp.phase==='upload'){pct=(_imp.i/_imp.n)*30;txt='Importing file '+(_imp.i+1)+' of '+_imp.n+' · '+_imp.name+(p.active&&p.phase==='Parsing'?' — parsing':'');}
   else{const sp=p.active?p.pct:0.02;pct=30+70*sp;txt='Analysing '+_imp.n+' file(s) · '+(p.active?(p.phase+(p.detail?' — '+p.detail:'')):'starting…');}
   topProg(true,pct,txt+'  ·  '+el+'s');_progShown=true;}
  else if(p.active){topProg(true,p.pct*100,p.phase+(p.detail?' — '+p.detail:''));_progShown=true;}
  else if(_progShown&&!_hold){topProg(false);_progShown=false;}
 }catch(e){}
 setTimeout(pollProgress,(_imp||_progShown)?250:1500);}
let _hold=false;
async function importFiles(files){const good=files.filter(f=>/\.(xml|nmap|gnmap)$/i.test(f.name));
 if(!good.length){$('importMsg').textContent='No supported files — use .xml, .nmap or .gnmap.';return;}
 logLine('Importing '+good.length+' file(s): '+good.map(f=>f.name).join(', '));
 _imp={i:0,n:good.length,name:good[0].name,phase:'upload'};_impT0=Date.now();let okc=0;
 for(let k=0;k<good.length;k++){const file=good[k];_imp.i=k;_imp.name=file.name;$('importMsg').textContent='Parsing '+file.name+' ('+(k+1)+'/'+good.length+')…';
  try{const r=await fetch('/api/import',{method:'POST',headers:{'X-Filename':file.name,'X-Defer':'1'},body:file});
   const j=await r.json().catch(()=>({}));
   if(r.ok&&j.ok){okc++;logLine('Scan file uploaded successfully: '+file.name+' ('+j.hosts_in_file+' hosts)');logLine('Nmap scan data parsed: '+file.name);}
   else{$('importMsg').textContent='Could not parse '+file.name+': '+((j&&j.error)||r.status);logLine('Import FAILED for '+file.name);}}
  catch(e){logLine('Import FAILED for '+file.name);}}
 _imp.phase='analyse';$('importMsg').textContent='Analysing '+okc+' file(s)…';
 try{await fetch('/api/analyse',{method:'POST'});}catch(e){}
 const secs=Math.round((Date.now()-_impT0)/1000);_imp=null;_hold=true;topProg(true,100,'Done — '+okc+' file(s) analysed in '+secs+'s');_progShown=true;
 $('importMsg').textContent='Done — analysis updated.';await refresh(true);
 setTimeout(()=>{_hold=false;topProg(false);_progShown=false;},1100);setTimeout(closeImport,650);}
/* ---------- save / download / pdf ---------- */
async function api(path,opts){const r=await fetch(path,opts||{});return {r,j:await r.json().catch(()=>({}))};}
async function saveFolder(){$('saveMsg').textContent='Saving report folder…';logLine('Save requested — building report folder');
 const {r,j}=await api('/api/save',{method:'POST'});
 $('saveMsg').textContent=r.ok?('Saved → '+j.folder+' ('+j.files+' files)'):('Save failed: '+(j.error||r.status));
 if(r.ok)logLine('Report folder saved: '+j.folder+' ('+j.files+' files)');}
function dl(kind,which){window.location='/api/download/'+kind+(which?('?which='+which):'');logLine('Download started: '+kind+(which?(' ('+which+')'):''));}
function exportPDF(){logLine('PDF export: opening print view in the current theme ('+SETTINGS.theme+') — choose “Save as PDF”');syncTheme();const w=window.open('/api/report/print','_blank');if(!w)window.location='/api/report/print';}
async function clearAll(){if(!confirm('Remove all loaded scan data from the page? (Files on disk are not touched.)'))return;
 await api('/api/clear',{method:'POST'});logLine('All loaded scan data cleared');refresh(true);}
/* ---------- terminate (1-step or 3-step by Settings) ---------- */
let termCtx=null;
function startTerminate(){togglePanel(false);
 if(SETTINGS.termSteps===1){if(confirm('Terminate Nmapilizer now? A final report (HTML + CSVs) is saved first.'))doTerminate();return;}
 termStep(1);}
function termStep(n){$('termOverlay').style.display='flex';const b=$('termBody');
 if(n===1)b.innerHTML='<p>This closes the tool completely. Before shutting down it saves <b>all current results</b> (full HTML report + findings &amp; exploits CSVs) into a <b>new report folder</b>.</p><div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn" onclick="termCancel()">Cancel</button><button class="btn danger" onclick="termStep(2)">Yes, terminate</button></div>';
 if(n===2)b.innerHTML='<p><b>Step 2 of 3 — confirm the save.</b></p><label style="display:flex;gap:8px;align-items:flex-start"><input type="radio" name="tsave" value="save" checked style="margin-top:3px"><span>Save everything first, then shut down <span class="mut">(recommended)</span></span></label><label style="display:flex;gap:8px;align-items:flex-start"><input type="radio" name="tsave" value="nosave" style="margin-top:3px"><span>Shut down WITHOUT saving</span></label><div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"><button class="btn" onclick="termCancel()">Cancel</button><button class="btn danger" onclick="termStep(3)">Continue</button></div>';
 if(n===3){termCtx={save:document.querySelector('input[name=tsave]:checked').value==='save'};
  b.innerHTML='<p><b>Step 3 of 3 — type TERMINATE to confirm.</b></p><input id="termTyped" type="text" placeholder="TERMINATE" autocomplete="off" style="width:100%;background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:9px"><div id="termMsg" class="mut small" style="margin-top:6px"></div><div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px"><button class="btn" onclick="termCancel()">Cancel</button><button class="btn danger" onclick="doTerminate()">Terminate now</button></div>';
  setTimeout(()=>$('termTyped').focus(),50);}}
function termCancel(){$('termOverlay').style.display='none';logLine('Terminate cancelled');}
async function doTerminate(){const body={};
 if(SETTINGS.termSteps===1){body.typed='TERMINATE';body.save=true;}
 else{const typed=($('termTyped')?$('termTyped').value:'');body.typed=typed;body.save=termCtx?termCtx.save:true;
  if(typed!=='TERMINATE'){$('termMsg').textContent='You typed "'+typed+'" — it must be exactly TERMINATE.';return;}}
 logLine('Terminate requested — final save, then shutdown');
 const {r,j}=await api('/api/terminate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 if(r.ok&&j.ok){document.body.innerHTML='<div style="max-width:640px;margin:12vh auto;text-align:center;font-family:Inter,system-ui"><h1>✔ Nmapilizer terminated</h1><p>'+(j.folder?('Final report saved to <b>'+esc(j.folder)+'</b> ('+j.files+' files).'):'Closed without saving.')+'</p><p class="mut">You can close this tab. Start again any time with: python3 nmapilizer_v5.py --serve</p></div>';}
 else if($('termMsg')){$('termMsg').textContent='Server refused: '+((j&&j.error)||r.status);}}
/* ---------- filters / refresh / boot ---------- */
function clearFilters(){['fSearch','fPort','fCVE'].forEach(i=>$(i).value='');['fSev','fSubnet','fService','fOS','fDevice'].forEach(i=>$(i).value='');$('fRisk').value='0';window._guideFocus=null;render();logLine('Filters cleared');}
let filterTimer=null;
['fSearch','fSev','fSubnet','fService','fOS','fDevice','fPort','fCVE','fRisk'].forEach(id=>{$(id).addEventListener('input',()=>{clearTimeout(filterTimer);filterTimer=setTimeout(()=>{if(TAB==='topology')topoSig='';window._pendingFilterLog='Filters applied';render();},220);});});
function fillFilterOptions(){const f=F();
 const fill=(id,vals,all)=>{const el=$(id);const cur=el.value;el.innerHTML='<option value="">'+all+'</option>'+vals.map(v=>'<option'+(v===cur?' selected':'')+'>'+esc(v)+'</option>').join('');};
 fill('fSubnet',[...new Set(DATA.hosts.map(h=>subnetOf(h.ip)))].sort(),'All subnets');
 fill('fService',[...new Set(DATA.hosts.flatMap(h=>(h.ports||[]).map(p=>(p.service||'').toLowerCase())))].filter(Boolean).sort(),'All services');
 fill('fOS',[...new Set(DATA.hosts.map(h=>osShort(h.os)))].sort(),'All OS');
 fill('fDevice',[...new Set(DATA.hosts.map(h=>deviceOf(h).name))].sort(),'All devices');}
async function refresh(force){try{const r=await fetch('/api/data');if(!r.ok)return;const d=await r.json();
 if(force||d.version!==lastVersion){const isFirst=lastVersion===-1;lastVersion=d.version;DATA=d;mergeServerActivity();fillFilterOptions();render();
  if(!isFirst&&!force)logLine('Data updated by file watcher');}}
 catch(e){}}
applySettings();buildMainNav();pollProgress();
logLine('Nmapilizer v5.4 dashboard loaded — sections are in the row under the header; Save & export are in the side panel (two-line handle on the far-left edge)');
refresh(true);
if(document.fonts&&document.fonts.ready)document.fonts.ready.then(()=>setTimeout(iconFallbackCheck,250));
setTimeout(iconFallbackCheck,2000);
try{if(!localStorage.getItem('nmapilizer5-help-seen'))setTimeout(showHelp,700);}catch(e){}
setInterval(()=>{if(SETTINGS.autoRefresh&&TAB!=='settings')refresh(false);},4000);
</script></body></html>
"""


# --------------------------------------------------------------------------
# v3 — standalone single-file HTML + CSV text (for web Download buttons)
# --------------------------------------------------------------------------
def build_standalone_html(ds, theme_override="", autoprint=False):
    """One self-contained HTML file of the current results (inline CSS)."""
    PRINTBAR = ('<div class="printbar noprint">To save as PDF: in the print window choose <u>Save as PDF</u> as the destination '
                '(tick “Background graphics” to keep the theme colours). <button onclick="window.print()">Print / Save PDF</button></div>')
    t = ds["totals"]
    host_rows = "".join(
        f'<tr><td><code>{esc(h["ip"])}</code></td><td>{esc(h["hostname"])}</td><td>{esc(h["os"] or "—")}</td>'
        f'<td>{len([p for p in h["ports"] if str(p["state"]).startswith("open")])}</td>'
        f'<td>{h["risk_score"]}/100</td><td>{_sev_pill(h["risk_level"])}</td></tr>' for h in
        sorted(ds["hosts"], key=lambda x: -x["risk_score"]))
    fhtml = "".join(
        f'<div class="finding {esc(f["severity"])}"><b>{_sev_pill(f["severity"])} <code>{esc(f["host"])}:{f["port"]}</code> — {esc(f["title"])}</b>'
        f'<div class="mut small">{esc(f["category"])} · {esc(f["service"])} · <code>{esc(f["banner"])}</code>'
        + (f' · {esc(f["cve"])}' if f["cve"] else '') + '</div>'
        f'<div>{esc(f["detail"])}</div>'
        + (f'<div><b>Fix:</b> {esc(f["remediation"])}</div>' if f["remediation"] else '') + '</div>'
        for f in ds["findings"])
    xrows = "".join(
        f'<tr><td>{_sev_pill(e["severity"])}</td><td><code>{esc(e["host"])}:{e["port"]}</code></td>'
        f'<td>{esc(e["service"])}</td><td>{esc(e["title"])}</td><td>{esc(e["cve"] or "—")}</td>'
        f'<td>{esc(e["source"])}</td><td>{esc(e["reference"])}</td></tr>' for e in ds["exploits"])
    cve_rows = _cve_table_rows(ds.get("cves", []), False) or '<tr><td colspan="12" class="mut">No CVEs identified.</td></tr>'
    guide_html = "".join(
        f'<div class="finding {esc(g["severity"])}"><b>{_sev_pill(g["severity"])} {esc(g["title"])}</b>'
        f'<div class="mut small">{esc(g["host"])}:{g["port"]} · {esc(g["service"])} · {esc(g["cve"])}</div>'
        f'<div>{esc(g["summary"])}</div>'
        + "".join(f"<pre>{esc(c['cmd'])}</pre>" for c in g["commands"])
        + f'<div><b>Remediation:</b> {esc(g["remediation"])}</div></div>' for g in ds.get("guides", [])) or '<p class="mut">No guides matched.</p>'
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="author" content="{AUTHOR_NAME}"><title>Nmapilizer Report — {esc(ds['generated'])}</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet"><link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200&display=swap" rel="stylesheet"><style>{CSS}{theme_override or theme_css("midnight")}</style></head>
<body>{PRINTBAR if autoprint else ""}<header><h1>🔎 Nmapilizer Report</h1><div class="mut">Saved from the live dashboard · {esc(ds['generated'])} · single-file export</div>{author_buttons()}</header>
<div class="wrap">
<div class="cards"><div class="card"><b>{t['hosts']}</b><span>Hosts</span></div>
<div class="card"><b>{t['open_ports']}</b><span>Open ports</span></div>
<div class="card"><b>{t['flagged_hosts']}</b><span>Flagged hosts</span></div>
<div class="card"><b>{t['findings']}</b><span>Findings</span></div>
<div class="card"><b>{t['exploits']}</b><span>Exploit matches</span></div></div>
<h2>Hosts</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open</th><th>Risk</th><th>Level</th></tr></thead><tbody>{host_rows}</tbody></table>
<h2>Findings ({len(ds['findings'])})</h2>{fhtml or '<p class="mut">No findings.</p>'}
<h2>Exploits / CVEs ({len(ds['exploits'])})</h2><table><thead><tr><th>Severity</th><th>Host:Port</th><th>Service</th><th>Exploit / Issue</th><th>CVE</th><th>Source</th><th>Reference</th></tr></thead><tbody>{xrows or '<tr><td colspan="7" class="mut">None.</td></tr>'}</tbody></table>
<h2>CVE register ({len(ds.get('cves', []))})</h2><table><thead><tr>{CVE_HEAD}</tr></thead><tbody>{cve_rows}</tbody></table>
<h2>Exploitation guides ({len(ds.get('guides', []))})</h2>{guide_html}
</div><footer>Generated by Nmapilizer {VERSION} from the live dashboard. Verify Critical/High findings manually.<br>Author: {author_html(compact=True)}</footer>
{"<script>window.addEventListener('load',function(){setTimeout(function(){window.print()},900)})</script>" if autoprint else ""}</body></html>"""

def csv_text(ds, which):
    """CSV string for one table (hosts/ports/findings/exploits) — web downloads."""
    rows = {
        "hosts": ds["hosts"],
        "ports": [{"ip": h["ip"], "hostname": h["hostname"], **p} for h in ds["hosts"] for p in h["ports"]],
        "findings": ds["findings"], "exploits": ds["exploits"],
    }[which]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_TABLES[which], extrasaction="ignore")
    w.writeheader()
    for r in rows: w.writerow(r)
    return buf.getvalue()

class LiveState:
    def __init__(self, use_searchsploit=True):
        self.hosts, self.metas = {}, []
        self.findings, self.exploits = [], []
        self.ss = Searchsploit()
        self.use_ss = use_searchsploit
        self.version = 0
        self.lock = threading.Lock()
        # v3: where the web Save / Terminate actions write report bundles
        self.report_base = Path(".")
        self.report_title = "Nmapilizer Report"
        self.report_opts = {"theme": "midnight"}
        self.theme_override = ""   # CSS of the dashboard's current theme, pushed by the browser
        self.activity = []
    def log_activity(self, msg, echo=False):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "msg": str(msg)}
        self.activity.append(entry)
        del self.activity[:-300]
        if echo: print(f"[{entry['time']}] {msg}", flush=True)
    def add_xml(self, text, name):
        return self.add_text(text, name)
    def add_text(self, text, name, defer=False):
        PROG.start("Parsing", name); PROG.update(0.05, force=True)
        hosts, meta = parse_any_text(text, name)
        with self.lock:
            merge_hosts(self.hosts, hosts, name)
            self.metas = [m for m in self.metas if m["source"] != name] + [meta]
            if not defer: self._reanalyse()
        if defer: PROG.done()
        return len(hosts)
    def add_file(self, path: Path, defer=False):
        PROG.start("Parsing", path.name); PROG.update(0.05, force=True)
        hosts, meta = parse_any_file(path)
        with self.lock:
            merge_hosts(self.hosts, hosts, path.name)
            self.metas = [m for m in self.metas if m["source"] != path.name] + [meta]
            if not defer: self._reanalyse()
        if defer: PROG.done()
        return len(hosts)
    def _reanalyse(self):
        self.findings, self.exploits = analyse(self.hosts, self.ss, self.use_ss)
        self.version += 1
    def dataset(self):
        ds = build_dataset(self.hosts, self.findings, self.exploits, self.metas)
        ds["activity"] = self.activity
        ds["version"] = self.version
        return ds
    def clear(self):
        with self.lock:
            self.hosts, self.metas, self.findings, self.exploits = {}, [], [], []
            self.version += 1

def make_handler(state: LiveState, on_terminate=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, code, body, ctype="application/json", headers=None):
            b = body if isinstance(body, bytes) else body.encode()
            self.send_response(code); self.send_header("Content-Type", ctype)
            for k, v in (headers or {}).items(): self.send_header(k, v)
            self.send_header("Content-Length", str(len(b))); self.end_headers()
            try: self.wfile.write(b)
            except (BrokenPipeError, ConnectionResetError): pass  # browser tab closed/refreshed mid-response — not an error
        def _save_bundle(self):
            """Write the full report bundle into a NEW auto-named report folder.
            Returns (folder Path, file count) or (None, 0) when nothing is loaded."""
            if not state.hosts: return None, 0
            with state.lock:
                out = next_report_dir(state.report_base)
                ropts = dict(state.report_opts); ropts["theme_override"] = state.theme_override
                generate_report(state.hosts, state.findings, state.exploits,
                                state.metas, out, state.report_title, ropts)
            nfiles = sum(1 for _ in out.rglob("*") if _.is_file())
            state.log_activity(f"Report saved → {out} ({nfiles} files: HTML + CSV + JSON)", echo=True)
            return out, nfiles
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                self._send(200, LIVE_HTML.replace("__CSS__", CSS + theme_css("midnight")).replace("__AUTHOR_COMPACT__", author_html(compact=True)).replace("__AUTHOR_CARD__", author_html()).replace("__VERSION__", VERSION), "text/html; charset=utf-8")
            elif path == "/api/data":
                self._send(200, json.dumps(state.dataset()))
            elif path == "/api/version":
                self._send(200, json.dumps({"version": state.version}))
            elif path == "/api/download/html":
                if not state.hosts:
                    self._send(400, json.dumps({"ok": False, "error": "no data loaded — import a scan first"}))
                else:
                    fname = f"Nmapilizer_Report_{datetime.now():%Y%m%d_%H%M%S}.html"
                    self._send(200, build_standalone_html(state.dataset(), state.theme_override), "text/html; charset=utf-8",
                               {"Content-Disposition": f'attachment; filename="{fname}"'})
            elif path == "/api/report/print":
                if not state.hosts:
                    self._send(400, json.dumps({"ok": False, "error": "no data loaded — import a scan first"}))
                else:  # inline (NOT an attachment) so the browser can open the print / Save-as-PDF dialog
                    self._send(200, build_standalone_html(state.dataset(), state.theme_override, autoprint=True), "text/html; charset=utf-8")
            elif path == "/api/download/csv":
                which = (parse_qs(urlparse(self.path).query).get("which") or ["findings"])[0]
                if which not in CSV_TABLES:
                    self._send(400, json.dumps({"ok": False, "error": f"unknown csv table '{which}'"}))
                elif not state.hosts:
                    self._send(400, json.dumps({"ok": False, "error": "no data loaded — import a scan first"}))
                else:
                    self._send(200, csv_text(state.dataset(), which), "text/csv; charset=utf-8",
                               {"Content-Disposition": f'attachment; filename="nmapilizer-{which}.csv"'})
            elif path == "/api/progress":
                self._send(200, json.dumps(PROG.snapshot()))
            else:
                self._send(404, json.dumps({"error": "not found"}))
        def do_POST(self):
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b""
            if path == "/api/import":
                name = self.headers.get("X-Filename", "upload.xml")
                try:
                    n = state.add_text(raw.decode("utf-8", errors="replace"), name, defer=(self.headers.get("X-Defer") == "1"))
                    state.log_activity(f"Imported {name} — {n} host(s) in file · {len(state.hosts)} hosts total · "
                                       f"{len(state.findings)} findings · {len(state.exploits)} exploit matches", echo=True)
                    self._send(200, json.dumps({"ok": True, "hosts_in_file": n, "version": state.version}))
                except Exception as e:
                    self._send(400, json.dumps({"ok": False, "error": str(e)}))
            elif path == "/api/analyse":      # one analysis pass after a batch of deferred imports
                try:
                    with state.lock: state._reanalyse()
                    state.log_activity(f"Analysis complete — {len(state.hosts)} hosts · {len(state.findings)} findings · "
                                       f"{len(state.exploits)} exploit matches", echo=True)
                    self._send(200, json.dumps({"ok": True, "version": state.version}))
                except Exception as e:
                    PROG.done(); self._send(500, json.dumps({"ok": False, "error": str(e)}))
            elif path == "/api/theme":
                try:
                    pl = json.loads(raw.decode("utf-8", errors="replace") or "{}")
                    state.theme_override = theme_css_from_vars(pl.get("vars"), pl.get("scheme", "dark"))
                    self._send(200, json.dumps({"ok": True}))
                except Exception as e:
                    self._send(400, json.dumps({"ok": False, "error": str(e)}))
            elif path == "/api/clear":
                state.clear(); state.log_activity("All loaded scan data cleared", echo=True)
                self._send(200, json.dumps({"ok": True}))
            elif path == "/api/save":
                try:
                    out, nfiles = self._save_bundle()
                    if out is None:
                        self._send(400, json.dumps({"ok": False, "error": "nothing to save — import a scan first"}))
                    else:
                        print(f"[save] report bundle written → {out}/ ({nfiles} files)", flush=True)
                        self._send(200, json.dumps({"ok": True, "folder": str(out), "files": nfiles}))
                except Exception as e:
                    self._send(500, json.dumps({"ok": False, "error": str(e)}))
            elif path == "/api/terminate":
                try: payload = json.loads(raw.decode("utf-8", errors="replace") or "{}")
                except Exception: payload = {}
                if payload.get("typed") != "TERMINATE":
                    self._send(400, json.dumps({"ok": False, "error": "final confirmation text 'TERMINATE' was not received — tool is still running"}))
                else:
                    try:
                        out, nfiles = self._save_bundle()
                    except Exception as e:
                        self._send(500, json.dumps({"ok": False, "error": f"save before closing failed: {e}"})); return
                    print(f"[terminate] {'saved → ' + str(out) + '/' if out else 'no data to save'} — shutting down as requested from the web page.", flush=True)
                    self._send(200, json.dumps({"ok": True, "folder": str(out) if out else None, "files": nfiles}))
                    if on_terminate: threading.Thread(target=on_terminate, daemon=True).start()
            else:
                self._send(404, json.dumps({"error": "not found"}))
    return H

def serve(state: LiveState, host, port, watch_dirs, open_browser=True):
    if watch_dirs:
        watched = {}
        def watcher():
            while True:
                changed = False
                for d in watch_dirs:
                    for ext in ("*.xml", "*.nmap", "*.gnmap"):
                        for f in sorted(Path(d).rglob(ext)):
                            try: mt = f.stat().st_mtime
                            except OSError: continue
                            if watched.get(str(f)) != mt:
                                watched[str(f)] = mt
                                try: state.add_file(f); print(f"[watch] reloaded {f}")
                                except Exception as e: print(f"[watch] {f}: {e}")
                                changed = True
                time.sleep(2)
        threading.Thread(target=watcher, daemon=True).start()
    holder = {}
    def _shutdown_later():
        time.sleep(0.7)
        try: holder["srv"].shutdown()
        except Exception: pass
    srv = ThreadingHTTPServer((host, port), make_handler(state, _shutdown_later))
    def _quiet_handle_error(request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)): return  # client went away mid-response — stay silent
        return ThreadingHTTPServer.handle_error(srv, request, client_address)
    srv.handle_error = _quiet_handle_error
    holder["srv"] = srv
    url = f"http://{host}:{port}/"
    print(f"\n  🔎 Nmapilizer live dashboard → {url}", flush=True)
    print(f"     Hosts loaded: {len(state.hosts)}")
    print("     In the page: sections row under the header · Save & export in the side panel (two-line handle) · Import popup · Padding toggle ·")
    print("     ⛔ Terminate button saves everything (HTML + CSVs) into a new report folder, then closes the tool.")
    print("     Or press Ctrl+C here to stop.\n")
    if open_browser:
        try: webbrowser.open(url)
        except Exception: pass
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\nStopped.")
    print("  ✔ Nmapilizer closed. Bye!")

# --------------------------------------------------------------------------
# v2 ENGINE — colour CLI, animated ASCII art, CSV export, themes, custom rules
# --------------------------------------------------------------------------
import ipaddress, math, random

COLOR_ENABLED = False
ANSI = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35",
        "cyan": "36", "white": "37", "grey": "90", "orange": "38;5;208", "brightred": "91"}
SEV_ANSI = {"Critical": "brightred", "High": "orange", "Medium": "yellow", "Low": "green", "Info": "grey", "Clean": "green"}

def setup_color(mode: str = "auto"):
    global COLOR_ENABLED
    if mode == "always": COLOR_ENABLED = True
    elif mode == "never": COLOR_ENABLED = False
    else:
        COLOR_ENABLED = bool(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    return COLOR_ENABLED

def paint(text, color=None, bold=False, dim=False):
    if not COLOR_ENABLED: return str(text)
    codes = []
    if bold: codes.append("1")
    if dim: codes.append("2")
    if color in ANSI: codes.append(ANSI[color])
    if not codes: return str(text)
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"

def sev_text(sev, text=None):
    return paint(text if text is not None else sev, SEV_ANSI.get(sev, "white"), bold=sev in ("Critical", "High"))

def ok(msg): print(paint("[+]", "green", bold=True) + " " + str(msg))
def warn(msg): print(paint("[!]", "red", bold=True) + " " + str(msg), file=sys.stderr)
def info(msg): print(paint("[*]", "cyan", bold=True) + " " + str(msg))

def print_cli_summary(ds, top=10):
    """Colourised terminal summary: totals, per-host risk, top findings."""
    t = ds["totals"]
    print("\n" + paint("=" * 72, "cyan"))
    print(paint(f"  NMAPILIZER {VERSION} — ANALYSIS COMPLETE", "cyan", bold=True))
    print(paint(f"  by {AUTHOR_NAME}  ·  github.com/buddysecurity  ·  youtube.com/@budsec  ·  instagram.com/thebudsec", "magenta"))
    print(paint("=" * 72, "cyan"))
    if ds.get("intel"):
        _i = ds["intel"]; _pc = Counter(c.get("priority", "P4") for c in ds.get("cves", []))
        print(paint(f"  Intel DB: {_i['cves']:,} CVEs · KEV {_i['kev']:,} · EPSS {_i['epss']:,} · EDB {_i['edb']:,} · MSF {_i['msf']:,} · updated {_i['updated'] or 'n/a'}", "cyan"))
        print("  CVE priority: " + "  ".join(f"{k} {_pc.get(k, 0)}" for k in ("P1", "P2", "P3", "P4")) +
              paint("   (P1=KEV exploited · P2=public exploit · P3=EPSS/CVSS high · P4=other)", dim=True))
    print(f"  Hosts: {paint(t['hosts'], bold=True)} ({t['hosts_up']} up)   "
          f"Open ports: {paint(t['open_ports'], bold=True)}   "
          f"Flagged hosts: {paint(t['flagged_hosts'], 'yellow' if t['flagged_hosts'] else 'green', bold=True)}")
    print("  Findings: " + "  ".join(f"{sev_text(s, s + ' ' + str(t['by_severity'][s]))}" for s in SEVERITIES)
          + f"   Exploits: {paint(t['exploits'], 'magenta', bold=True)}")
    print(paint("\n  HOST RISK", "blue", bold=True))
    for h in sorted(ds["hosts"], key=lambda x: -x["risk_score"]):
        bar = "█" * (h["risk_score"] // 5) + "░" * (20 - h["risk_score"] // 5)
        print(f"  {h['ip']:<16} {paint(bar, SEV_ANSI.get(h['risk_level'], 'grey'))} "
              f"{h['risk_score']:>3}/100  {sev_text(h['risk_level'])}  {paint(h['hostname'], dim=True)}")
    if ds["findings"]:
        print(paint(f"\n  TOP {min(top, len(ds['findings']))} FINDINGS — manual review queue", "blue", bold=True))
        for f in ds["findings"][:top]:
            print(f"  {sev_text(f['severity'], '[' + f['severity'].upper() + ']'):<28} "
                  f"{paint(f['host'] + ':' + str(f['port']), 'cyan')}  {f['title']}")
    print(paint("=" * 72, "cyan") + "\n")

# ----- themes -------------------------------------------------------------
THEMES = {
    "dark":     {},
    "light":    {"--bg": "#edf1f7", "--panel": "#ffffff", "--panel2": "#e6ecf4", "--line": "#ccd6e4",
                 "--txt": "#132033", "--mut": "#52677e", "--acc": "#0b6bcb",
                 "--hover": "#e8f0fb", "--codebg": "#edf2f8", "--codefg": "#0b5394", "--onacc": "#ffffff",
                 "--shadow": "0 1px 2px rgba(16,42,80,.08),0 6px 18px rgba(16,42,80,.07)",
                 "--danger": "#b3261e", "--crit": "#c62828", "--high": "#b84a05", "--med": "#8a5a00", "--low": "#1a7f37",
                 "--info": "#52677e", "color-scheme": "light"},
    "midnight": {"--bg": "#070a1a", "--panel": "#10142e", "--panel2": "#181e42", "--line": "#2a3170",
                 "--txt": "#dfe6ff", "--mut": "#8d97c9", "--acc": "#8b7ff0",
                 "--hover": "#1b2150", "--codebg": "#0a0d24", "--codefg": "#ffd479", "--onacc": "#ffffff",
                 "--shadow": "0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.3)"},
    "forest":   {"--bg": "#0b140e", "--panel": "#122017", "--panel2": "#182b1f", "--line": "#274435",
                 "--txt": "#e2f2e6", "--mut": "#8fb89d", "--acc": "#4ade80",
                 "--hover": "#173826", "--codebg": "#0a1810", "--codefg": "#ffd479", "--onacc": "#07280f",
                 "--shadow": "0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28)"},
    "solar":    {"--bg": "#171106", "--panel": "#241a0a", "--panel2": "#31230e", "--line": "#4d3a17",
                 "--txt": "#fdf0d0", "--mut": "#c2ab72", "--acc": "#ffb224",
                 "--hover": "#3a2a12", "--codebg": "#1d1508", "--codefg": "#ffd479", "--onacc": "#2a1a00",
                 "--shadow": "0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.28)"},
}
def theme_css(theme="dark", accent=""):
    vars_ = dict(THEMES.get(theme or "dark", {}))
    if accent:
        if re.fullmatch(r"#[0-9a-fA-F]{6}", accent.strip()): vars_["--acc"] = accent.strip()
    if not vars_: return ""
    body = ";".join(f"{k}:{v}" for k, v in vars_.items())
    return f"\n/* v2 theme: {theme} */\n:root{{{body}}}\n"

# ----- CSV export -----------------------------------------------------------
CSV_TABLES = {
    "hosts":    ["ip", "hostname", "status", "os", "mac", "vendor", "risk_score", "risk_level"],
    "ports":    ["ip", "hostname", "protocol", "port", "state", "service", "product", "version", "extrainfo", "banner"],
    "findings": ["host", "hostname", "port", "protocol", "service", "banner", "severity", "category", "title", "detail", "cve", "reference", "remediation", "priority", "confidence"],
    "exploits": ["host", "port", "service", "title", "severity", "cve", "source", "reference", "detail", "priority", "confidence"],
}
def export_csvs(ds, directory: Path, delimiter=",", prefix=""):
    """Write hosts/ports/findings/exploits CSVs. Returns list of Paths written."""
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    rows = {
        "hosts": ds["hosts"],
        "ports": [{"ip": h["ip"], "hostname": h["hostname"], **p} for h in ds["hosts"] for p in h["ports"]],
        "findings": ds["findings"], "exploits": ds["exploits"],
    }
    written = []
    for name, fields in CSV_TABLES.items():
        path = directory / f"{prefix}{name}.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", delimiter=delimiter)
            w.writeheader()
            for r in rows[name]: w.writerow(r)
        written.append(path)
    return written

def csv_delimiter(spec: str):
    return {"comma": ",", "semicolon": ";", "tab": "\t", "pipe": "|"}.get((spec or "comma").lower(),
                                                                         (spec or ",")[:1] or ",")

def prune_formats(out_root: Path, formats):
    """Remove bundle file types the user did not ask for (--format)."""
    if "csv" not in formats:
        for f in out_root.glob("*.csv"): f.unlink()
    if "json" not in formats and (out_root / "data.json").exists(): (out_root / "data.json").unlink()
    if "txt" not in formats and (out_root / "summary.txt").exists(): (out_root / "summary.txt").unlink()
    if "html" not in formats:
        for f in out_root.glob("*.html"): f.unlink()
        shutil.rmtree(out_root / "assets", ignore_errors=True)

# ----- config + custom rules ------------------------------------------------
def load_config_file(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        warn(f"could not read --config {path}: {e}"); return {}

def load_custom_rules(path):
    """JSON: {"dangerous_ports":{"9999":{"name":"X","severity":"High","why":"..","fix":".."}},
              "outdated":[{"pattern":"product","below":"1.2.3","severity":"High","cve":"CVE-..","title":"..","advice":".."}],
              "exploits":[{"pattern":"product 1.0","title":"..","severity":"Critical","cve":"..","edb":"..","msf":".."}],
              "highlights":[{"keyword":"staging","severity":"Medium"}]}"""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        warn(f"could not read --custom-rules {path}: {e}"); return "unreadable"
    n = 0
    for port, spec in (data.get("dangerous_ports") or {}).items():
        try:
            DANGEROUS_PORTS[int(port)] = (spec.get("name", f"Custom service {port}"),
                spec.get("severity", "Medium"), spec.get("why", "Flagged by your custom rules."),
                spec.get("fix", "Review per your internal standard.")); n += 1
        except Exception: pass
    for r in data.get("outdated") or []:
        vt = parse_version(str(r.get("below", "")))
        if vt and r.get("pattern"):
            OUTDATED_RULES.append((r["pattern"], vt, r.get("severity", "Medium"), r.get("cve", ""),
                                   r.get("title", "Custom outdated rule matched"),
                                   r.get("advice", "Flagged by your custom rules — upgrade or review."))); n += 1
    for r in data.get("exploits") or []:
        if r.get("pattern"):
            EXPLOIT_DB.append((r["pattern"], r.get("title", "Custom exploit match"), r.get("severity", "High"),
                               r.get("cve", ""), r.get("edb", "custom rules"), r.get("msf", ""))); n += 1
    for r in data.get("highlights") or []:
        kw = r.get("keyword") if isinstance(r, dict) else str(r)
        sev = r.get("severity", "Medium") if isinstance(r, dict) else "Medium"
        if kw: HIGHLIGHTS.append((kw, sev)); n += 1
    return n

def parse_port_set(specs):
    out = set()
    for spec in specs or []:
        for part in str(spec).split(","):
            part = part.strip()
            if not part: continue
            if "-" in part:
                a, b = part.split("-", 1)
                out.update(range(int(a), int(b) + 1))
            else: out.add(int(part))
    return out

def host_selected(ip, hostname, includes, excludes):
    def matches(patterns):
        for pat in patterns or []:
            pat = str(pat).strip()
            if not pat: continue
            try:
                if "/" in pat and ipaddress.ip_address(ip) in ipaddress.ip_network(pat, strict=False): return True
            except ValueError: pass
            if pat.lower() == ip.lower() or pat.lower() in (hostname or "").lower(): return True
        return False
    if excludes and matches(excludes): return False
    if includes and not matches(includes): return False
    return True

# ----- animated ASCII art ---------------------------------------------------
LOGO_LINES = [
    r"  _   _ __  __   _   ____ ___ _     ___ _____ _____ ____  ",
    r" | \ | |  \/  | / \ |  _ \_ _| |   |_ _|_  /| ____|  _ \ ",
    r" |  \| | |\/| |/ _ \| |_) | || |    | |  / / |  _| | |_) |",
    r" | |\  | |  | / ___ \  __/| || |___ | | / /_ | |___|  _ < ",
    r" |_| \_|_|  |_/_/ \_\_|  |___|_____|___/____|_____|_| \_\ ",
]
LOGO_COLORS = ["cyan", "blue", "magenta", "magenta", "cyan"]
SPINNERS = "|/-\\"

def _radar_lines(tick):
    rows, cols, cy, cx = 7, 23, 3, 11
    theta = (tick % 16) / 16 * 2 * math.pi
    blips = [(1, 5), (2, 17), (4, 6), (5, 15), (3, 19)]
    grid = [[" "] * cols for _ in range(rows)]
    for y in range(rows):
        for x in range(cols):
            d = math.sqrt(((x - cx) / 10.5) ** 2 + ((y - cy) / 3.2) ** 2)
            if abs(d - 1.0) < 0.16: grid[y][x] = "."
            elif abs(d - 0.55) < 0.10: grid[y][x] = ":"
    for k in range(1, 10):
        for trail, ch in ((0, "*"), (1, "+"), (2, ".")):
            a = theta - trail * 0.22
            x = int(round(cx + math.cos(a) * k * 1.12)); y = int(round(cy + math.sin(a) * k * 0.36))
            if 0 <= y < rows and 0 <= x < cols and grid[y][x] in " .:": grid[y][x] = ch
    grid[cy][cx] = "@"
    for (y, x) in blips:
        # blip lights up as the sweep passes its angle
        ba = math.atan2((y - cy) / 0.36, (x - cx) / 1.12)
        diff = (theta - ba) % (2 * math.pi)
        grid[y][x] = "O" if diff < 1.2 else "o"
    return ["  " + "".join(r) for r in grid]

def _wave_lines(tick):
    cols, rows = 34, 6
    heights = [int((math.sin(i * 0.55 + tick * 0.7) * 0.5 + 0.5) * (rows - 1)) +
               int((math.cos(i * 0.23 - tick * 0.4) * 0.5 + 0.5) * 1.5) for i in range(cols)]
    out = []
    for level in range(rows - 1, -1, -1):
        out.append("  " + "".join("#" if h >= level else ("=" if h == level - 1 else " ") for h in heights))
    return out

def _matrix_lines(tick):
    rng = random.Random(42)
    cols, rows = 40, 6
    out = []
    for r in range(rows):
        line = ""
        for c in range(cols):
            v = rng.random()
            ch = rng.choice("01<>[]{}#$%&")
            drop = (tick + c * 3 + r * 7) % 11
            line += ch if drop in (r, (r + 5) % 11) or v > 0.93 else " "
        out.append("  " + line)
    return out

ART_STYLES = {"radar": _radar_lines, "wave": _wave_lines, "matrix": _matrix_lines}

class AnimatedArt:
    """Live, coloured, moving ASCII art on stderr until stop() is called.
    With total_seconds set (fake-run mode) it also shows a countdown + progress bar."""
    def __init__(self, style="radar", total_seconds=None, stream=None):
        self.style = style if style in ART_STYLES else "radar"
        self.total = total_seconds
        self.stream = stream or sys.stderr
        self.status = "Analysing scan data…"
        self._stop = threading.Event(); self._thread = None
        self._drawn = 0; self._t0 = time.time()
    def start(self):
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True); self._thread.start()
        return self
    def _render(self, tick):
        elapsed = time.time() - self._t0
        lines = [paint(t, LOGO_COLORS[i % len(LOGO_COLORS)], bold=True) for i, t in enumerate(LOGO_LINES)]
        lines += [paint(l, "green" if self.style != "matrix" else "green") for l in ART_STYLES[self.style](tick)]
        spin = SPINNERS[tick % 4]
        mm, ss = divmod(int(elapsed), 60)
        if self.total:
            remain = max(0.0, self.total - elapsed)
            rm, rs = divmod(int(math.ceil(remain)), 60)
            frac = min(1.0, elapsed / self.total) if self.total else 1
            bar = "█" * int(frac * 30) + "░" * (30 - int(frac * 30))
            lines.append(paint(f"  {spin} {self.status}", "white"))
            lines.append(f"  {paint('[' + bar + ']', 'cyan')} {paint(f'{frac*100:5.1f}%', 'cyan', bold=True)}"
                         f"  elapsed {paint(f'{mm:02d}:{ss:02d}', bold=True)} / {int(self.total):02d}s"
                         f"  remaining {paint(f'{rm:02d}:{rs:02d}', 'yellow', bold=True)}")
        else:
            dots = "." * (tick % 4)
            lines.append(paint(f"  {spin} {self.status}{dots}", "white"))
            lines.append(f"  elapsed {paint(f'{mm:02d}:{ss:02d}', 'cyan', bold=True)}   "
                         + paint("(live — stops automatically when the analysis finishes)", dim=True))
        return lines
    def _run(self):
        tick = 0
        try: self.stream.write("\x1b[?25l")
        except Exception: pass
        while not self._stop.is_set():
            lines = self._render(tick)
            out = ""
            if self._drawn: out += f"\x1b[{self._drawn}A"
            for ln in lines: out += "\x1b[2K" + ln + "\r\n"
            try: self.stream.write(out); self.stream.flush()
            except Exception: break
            self._drawn = len(lines); tick += 1
            self._stop.wait(0.12)
    def stop(self, final=""):
        self._stop.set()
        if self._thread: self._thread.join(timeout=1)
        try:
            if self._drawn: self.stream.write(f"\x1b[{self._drawn}A" + "\x1b[0J")
            self.stream.write("\x1b[?25h"); self.stream.flush()
        except Exception: pass
        if final: print(final)

def run_fake_animation(seconds, style="radar"):
    """--fake-run: play the art for exactly `seconds` (default 10) with timer, doing nothing else."""
    anim = AnimatedArt(style=style, total_seconds=seconds)
    anim.status = f"Fake run — simulating a scan for {int(seconds)} seconds…"
    anim.start()
    try: time.sleep(seconds)
    except KeyboardInterrupt: pass
    anim.stop(paint(f"  ✔ Fake run complete — {int(seconds)} seconds elapsed.", "green", bold=True))

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
# ==========================================================================
# v7 — LOCAL VULNERABILITY INTELLIGENCE (SQLite) + PREREQUISITE PRECHECK
#   NVD (CVE + affected CPE ranges + CVSS) · CISA KEV · EPSS · Exploit-DB CSV
#   · Metasploit module metadata  ->  one offline SQLite file, queried by CPE.
# Stdlib only. Nothing here scans a target or runs an exploit.
# ==========================================================================
INTEL = None                       # VulnIntel instance once the precheck passes
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")
DB_MAX_AGE_DAYS = 7
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URLS = ["https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
             "https://epss.cyentia.com/epss_scores-current.csv.gz"]
EDB_CSV_URLS = ["https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
                "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"]
PRIORITY_TEXT = {"P1": "Known exploited in the wild (CISA KEV)",
                 "P2": "Public exploit / Metasploit module exists",
                 "P3": "High EPSS (>=10%) or CVSS >= 7.0",
                 "P4": "Other / lower priority"}
CONF_RANK = {"CPE match": 0, "NSE script": 1, "Built-in rule": 2, "Banner guess": 3}
PRODUCT_ALIASES = {  # Nmap product text -> NVD product slug (used only when Nmap gave no CPE)
    "apache httpd": "http_server", "openssh": "openssh", "nginx": "nginx", "mysql": "mysql",
    "mariadb": "mariadb", "postgresql db": "postgresql", "isc bind": "bind", "samba smbd": "samba",
    "openssl": "openssl", "apache tomcat": "tomcat", "apache tomcat/coyote jsp engine": "tomcat",
    "microsoft iis httpd": "internet_information_services", "exim smtpd": "exim",
    "postfix smtpd": "postfix", "dovecot imapd": "dovecot", "dovecot pop3d": "dovecot",
    "proftpd": "proftpd", "vsftpd": "vsftpd", "lighttpd": "lighttpd", "php": "php",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve(id TEXT PRIMARY KEY, published TEXT, cvss REAL, severity TEXT, descr TEXT);
CREATE TABLE IF NOT EXISTS cpem(cve TEXT, vendor TEXT, product TEXT, ver TEXT, vsi TEXT, vse TEXT, vei TEXT, vee TEXT);
CREATE INDEX IF NOT EXISTS ix_cpem_vp ON cpem(vendor, product);
CREATE INDEX IF NOT EXISTS ix_cpem_p ON cpem(product);
CREATE INDEX IF NOT EXISTS ix_cpem_cve ON cpem(cve);
CREATE TABLE IF NOT EXISTS kev(cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, added TEXT, ransomware TEXT);
CREATE TABLE IF NOT EXISTS epss(cve TEXT PRIMARY KEY, score REAL, pct REAL);
CREATE TABLE IF NOT EXISTS edb(edb TEXT, cve TEXT, title TEXT, etype TEXT, platform TEXT, verified TEXT);
CREATE INDEX IF NOT EXISTS ix_edb_cve ON edb(cve);
CREATE TABLE IF NOT EXISTS msf(cve TEXT, module TEXT, name TEXT, rank INTEGER);
CREATE INDEX IF NOT EXISTS ix_msf_cve ON msf(cve);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

def default_db_path(cli_value=""):
    return Path(cli_value or os.environ.get("NMAPILIZER_DB") or (Path.home() / ".nmapilizer" / "vulndb.sqlite"))

def sev_from_cvss(score):
    if score is None: return "Medium"
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low" if score > 0 else "Info"

def short_text(text, n=110):
    """First sentence, cut on a word boundary — never mid-word."""
    t = re.sub(r"\s+", " ", (text or "")).strip()
    if not t: return ""
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    first = m.group(1) if m else t
    if len(first) <= n: return first
    cut = first[:n].rsplit(" ", 1)[0].rstrip(",;:-([ ")
    return cut + "…"
def full_text(text, n=700):
    t = re.sub(r"\s+", " ", (text or "")).strip()
    if len(t) <= n: return t
    return t[:n].rsplit(" ", 1)[0].rstrip(",;:-([ ") + "…"

def priority_of(info):
    """P1 KEV · P2 public exploit/MSF module · P3 EPSS>=10% or CVSS>=7 · P4 rest."""
    if info.get("kev"): return "P1"
    if info.get("edb") or info.get("msf"): return "P2"
    if (info.get("epss") or 0) >= 0.10 or (info.get("cvss") or 0) >= 7.0: return "P3"
    return "P4"

# ---- version / CPE matching ------------------------------------------------
def _canon(v):
    return re.sub(r"[-_]?p\d+$", "", (v or "").lower().strip())
def _has_alpha(v):
    return bool(re.search(r"[a-z]", v or ""))
def ver_hit(ver, crit, vsi, vse, vei, vee):
    """Does service version `ver` fall inside one NVD CPE-match entry?"""
    vt = parse_version(ver)
    if crit not in ("*", "-", ""):
        if _canon(crit) == _canon(ver): return True
        c, v = _canon(crit), _canon(ver)
        return bool(vt and not _has_alpha(c) and not _has_alpha(v) and parse_version(crit) == vt)
    if crit == "-": return False
    if not (vsi or vse or vei or vee): return bool(vt)      # NVD: every version affected
    if not vt: return False
    def chk(bound, fn):
        bt = parse_version(bound)
        return True if (not bound or bt is None) else fn(bt)
    return (chk(vsi, lambda b: not vlt(vt, b)) and chk(vse, lambda b: vlt(b, vt)) and
            chk(vei, lambda b: not vlt(b, vt)) and chk(vee, lambda b: vlt(vt, b)))

def svc_ident(p):
    """Port -> (vendor, product, version, confidence) or None. Prefers Nmap's CPE."""
    for c in (p.cpes or []):
        m = re.match(r"cpe:/a:([^:]+):([^:]+)(?::([^:]+))?", c or "")
        if m:
            ven, prod, ver = (urllib.parse.unquote(x) if x else "" for x in m.groups())
            ver = ver or p.version
            if ver: return (ven.lower(), prod.lower(), ver, "CPE match")
    prod = (p.product or "").lower().strip()
    if prod and p.version:
        slug = PRODUCT_ALIASES.get(prod) or re.sub(r"[^a-z0-9]+", "_", prod).strip("_")
        return (None, slug, p.version, "Banner guess")
    return None

# ---- network helpers -------------------------------------------------------
def _http_get(url, headers=None, timeout=90, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Nmapilizer/" + VERSION, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 502, 503, 504): time.sleep(8 * (i + 1)); continue
            raise
        except Exception as e:
            last = e; time.sleep(3 * (i + 1))
    raise last

def _net_ok(host="services.nvd.nist.gov", port=443, timeout=6):
    try:
        socket.create_connection((host, port), timeout=timeout).close(); return True
    except Exception:
        return False

_last_bar = [0.0]
def _bar(label, done, total, extra=""):
    if not sys.stderr.isatty(): return
    now = time.time()
    if done < total and now - _last_bar[0] < 0.15: return
    _last_bar[0] = now
    frac = (done / total) if total else 0
    fill = int(28 * frac)
    line = f"  {label:<9} ▕{'█' * fill}{'░' * (28 - fill)}▏ {frac * 100:5.1f}%  {extra}"
    sys.stderr.write("\r" + line[:112].ljust(112)); sys.stderr.flush()
def _bar_end():
    if sys.stderr.isatty(): sys.stderr.write("\r" + " " * 112 + "\r"); sys.stderr.flush()

# ---- locate searchsploit / metasploit data on disk ---------------------------
def find_edb_csv(ss_bin=None):
    cands = []
    for rc in (Path.home() / ".searchsploit_rc", Path("/etc/.searchsploit_rc")):
        try: cands += [Path(x) for x in re.findall(r'["\'](/[^"\']+)["\']', rc.read_text())]
        except Exception: pass
    if ss_bin:
        real = Path(os.path.realpath(ss_bin)); cands += [real.parent, real.parent.parent / "share" / "exploitdb"]
    cands += [Path(p) for p in ("/usr/share/exploitdb", "/opt/exploitdb", "/usr/local/share/exploitdb",
              "/opt/homebrew/share/exploitdb", "/usr/local/opt/exploitdb/share/exploitdb")]
    cands += [Path.home() / "exploitdb", Path.home() / ".exploitdb"]
    for c in cands:
        f = c / "files_exploits.csv"
        if f.is_file(): return f
    return None

def find_msf_meta(msf_bin=None):
    cands = [Path(p) for p in ("/usr/share/metasploit-framework/db/modules_metadata_base.json",
             "/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json",
             "/usr/local/share/metasploit-framework/db/modules_metadata_base.json",
             "/opt/metasploit/embedded/framework/db/modules_metadata_base.json")]
    if msf_bin:
        real = Path(os.path.realpath(msf_bin))
        for up in (real.parent, real.parent.parent, real.parent.parent.parent):
            for sub in ("db", "embedded/framework/db", "framework/db", "share/metasploit-framework/db"):
                cands.append(up / sub / "modules_metadata_base.json")
    cands += [Path(p) for p in glob.glob("/usr/share/*/db/modules_metadata_base.json")]
    cands.append(Path.home() / ".msf4" / "store" / "modules_metadata.json")
    for c in cands:
        if c.is_file(): return c
    return None

# ---- the database ------------------------------------------------------------
class VulnIntel:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.con = sqlite3.connect(str(self.path), check_same_thread=False)
        self.con.executescript(SCHEMA)
        self._cache, self._mcache = {}, {}
        self.extra_edb, self.extra_msf = {}, {}     # runtime lookups (searchsploit --cve / msfconsole)
        self._counts = None
    def meta(self, k, default=""):
        with self.lock:
            r = self.con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else default
    def set_meta(self, k, v):
        with self.lock, self.con:
            if v is None: self.con.execute("DELETE FROM meta WHERE k=?", (k,))
            else: self.con.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v)))
    def count(self, table):
        expr = {"edb": "COUNT(DISTINCT edb)", "msf": "COUNT(DISTINCT module)"}.get(table, "COUNT(*)")
        with self.lock:
            return self.con.execute(f"SELECT {expr} FROM {table}").fetchone()[0]
    def counts(self, refresh=False):
        if self._counts is None or refresh:
            self._counts = {t: self.count(t) for t in ("cve", "cpem", "kev", "epss", "edb", "msf")}
        return self._counts
    def ready(self):
        return bool(self.meta("nvd_last")) and not self.meta("nvd_resume") and self.count("cpem") > 0
    def age_days(self):
        u = self.meta("updated")
        if not u: return None
        try: return (datetime.now() - datetime.fromisoformat(u)).total_seconds() / 86400
        except Exception: return None
    def summary(self):
        c = self.counts()
        return {"path": str(self.path), "cves": c["cve"], "cpe_rows": c["cpem"], "kev": c["kev"], "epss": c["epss"],
                "edb": c["edb"], "msf": c["msf"], "updated": self.meta("updated"),
                "age_days": (round(self.age_days(), 1) if self.age_days() is not None else None)}
    def match(self, vendor, product, version):
        """CVE ids whose NVD CPE ranges include this product/version."""
        key = (vendor, product, version)
        if key in self._mcache: return self._mcache[key]
        with self.lock:
            if vendor:
                rows = self.con.execute("SELECT cve,ver,vsi,vse,vei,vee FROM cpem WHERE vendor=? AND product=?", (vendor, product)).fetchall()
            else:
                rows = self.con.execute("SELECT cve,ver,vsi,vse,vei,vee FROM cpem WHERE product=?", (product,)).fetchall()
        hits = sorted({r[0] for r in rows if ver_hit(version, r[1], r[2], r[3], r[4], r[5])})
        self._mcache[key] = hits
        return hits
    def cve_info(self, cve):
        with self.lock:
            info = self._cache.get(cve)
            if info is None:
                c = self.con
                r = c.execute("SELECT cvss,severity,descr,published FROM cve WHERE id=?", (cve,)).fetchone()
                k = c.execute("SELECT vendor,product,name,added,ransomware FROM kev WHERE cve=?", (cve,)).fetchone()
                e = c.execute("SELECT score,pct FROM epss WHERE cve=?", (cve,)).fetchone()
                edb = [{"edb": a, "title": b, "type": t, "platform": p, "verified": v} for a, b, t, p, v in
                       c.execute("SELECT edb,title,etype,platform,verified FROM edb WHERE cve=? ORDER BY verified DESC LIMIT 6", (cve,))]
                msf = [{"module": m, "name": n, "rank": rk} for m, n, rk in
                       c.execute("SELECT module,name,rank FROM msf WHERE cve=? ORDER BY rank DESC LIMIT 6", (cve,))]
                info = {"cve": cve, "cvss": r[0] if r else None, "severity": (r[1] if r else "") or "",
                        "descr": (r[2] if r else "") or "", "published": (r[3] if r else "") or "",
                        "in_nvd": bool(r),
                        "kev": ({"vendor": k[0], "product": k[1], "name": k[2], "added": k[3], "ransomware": k[4]} if k else None),
                        "epss": e[0] if e else None, "epss_pct": e[1] if e else None, "edb": edb, "msf": msf}
                self._cache[cve] = info
        out = dict(info)
        if cve in self.extra_edb: out["edb"] = out["edb"] + [x for x in self.extra_edb[cve] if x["edb"] not in {y["edb"] for y in out["edb"]}]
        if cve in self.extra_msf: out["msf"] = out["msf"] + [x for x in self.extra_msf[cve] if x["module"] not in {y["module"] for y in out["msf"]}]
        return out

# ---- updaters (each returns a short result string; raises on failure) ---------
def update_kev(intel):
    data = json.loads(_http_get(KEV_URL))
    rows = [(v.get("cveID", ""), v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", ""),
             v.get("dateAdded", ""), v.get("knownRansomwareCampaignUse", "")) for v in data.get("vulnerabilities", [])]
    with intel.lock, intel.con:
        intel.con.execute("DELETE FROM kev"); intel.con.executemany("INSERT OR REPLACE INTO kev VALUES(?,?,?,?,?,?)", rows)
    return f"{len(rows):,} known-exploited CVEs"

def update_epss(intel):
    last = None
    for url in EPSS_URLS:
        try:
            raw = gzip.decompress(_http_get(url, timeout=120)).decode("utf-8", "replace"); break
        except Exception as e:
            last = e; raw = None
    if raw is None: raise last
    lines = [l for l in raw.splitlines() if l and not l.startswith("#")]
    rows = []
    for rec in csv.DictReader(lines):
        try: rows.append((rec["cve"], float(rec["epss"]), float(rec["percentile"])))
        except Exception: continue
    with intel.lock, intel.con:
        intel.con.execute("DELETE FROM epss"); intel.con.executemany("INSERT OR REPLACE INTO epss VALUES(?,?,?)", rows)
    return f"{len(rows):,} EPSS scores"

def update_edb(intel, ss_bin=None):
    p = find_edb_csv(ss_bin); src = "local searchsploit data"
    if p: text = p.read_text(encoding="utf-8", errors="replace")
    else:
        src = "downloaded"; last = None; text = None
        for url in EDB_CSV_URLS:
            try: text = _http_get(url, timeout=120).decode("utf-8", "replace"); break
            except Exception as e: last = e
        if text is None: raise last
    rows = []
    for rec in csv.DictReader(io.StringIO(text)):
        for cve in sorted(set(CVE_RX.findall(rec.get("codes", "") or ""))):
            rows.append((rec.get("id", ""), cve, rec.get("description", ""), rec.get("type", ""),
                         rec.get("platform", ""), rec.get("verified", "")))
    with intel.lock, intel.con:
        intel.con.execute("DELETE FROM edb"); intel.con.executemany("INSERT INTO edb VALUES(?,?,?,?,?,?)", rows)
    return f"{len({r[0] for r in rows}):,} CVE-mapped exploits ({src})"

def update_msf(intel, msf_bin=None):
    p = find_msf_meta(msf_bin)
    if not p: raise RuntimeError("Metasploit module metadata file not found (will fall back to msfconsole searches)")
    data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    rows = []
    for full, m in data.items():
        if not (full.startswith("exploit/") or full.startswith("auxiliary/")): continue
        for ref in m.get("references", []) or []:
            if isinstance(ref, str) and ref.upper().startswith("CVE-"):
                rows.append((ref.upper(), full, m.get("name", ""), int(m.get("rank", 0) or 0)))
    with intel.lock, intel.con:
        intel.con.execute("DELETE FROM msf"); intel.con.executemany("INSERT INTO msf VALUES(?,?,?,?)", rows)
    return f"{len({r[1] for r in rows}):,} Metasploit modules with CVE refs"

def _nvd_rows(item):
    c = item.get("cve", {}); cid = c.get("id", "")
    descr = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score = None
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if c.get("metrics", {}).get(k):
            try: score = float(c["metrics"][k][0]["cvssData"]["baseScore"]); break
            except Exception: pass
    cpe_rows = []
    for conf in c.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for cm in node.get("cpeMatch", []) or []:
                if not cm.get("vulnerable", True): continue
                parts = (cm.get("criteria") or "").split(":")
                if len(parts) < 6 or parts[2] != "a": continue
                cpe_rows.append((cid, parts[3].lower(), parts[4].lower(), parts[5],
                                 cm.get("versionStartIncluding", ""), cm.get("versionStartExcluding", ""),
                                 cm.get("versionEndIncluding", ""), cm.get("versionEndExcluding", "")))
    return (cid, c.get("published", ""), score, sev_from_cvss(score) if score is not None else "", descr), cpe_rows

def update_nvd(intel, api_key="", replace=None):
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.8 if api_key else 6.3
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    last, resume = intel.meta("nvd_last"), intel.meta("nvd_resume")
    if last and not resume:
        mode, windows, start = "incremental", [], datetime.fromisoformat(last)
        while start < now:
            end = min(start + timedelta(days=100), now); windows.append((start, end)); start = end
        replace = True
    else:
        mode, windows = "full", [None]
        if not resume: intel.set_meta("nvd_build_start", now.isoformat())
        replace = bool(resume)
    new_cves = 0
    for w in windows:
        idx = int(resume) if (mode == "full" and resume) else 0
        while True:
            q = {"resultsPerPage": 2000, "startIndex": idx}
            if w:
                q["lastModStartDate"] = w[0].strftime("%Y-%m-%dT%H:%M:%S.000")
                q["lastModEndDate"] = w[1].strftime("%Y-%m-%dT%H:%M:%S.000")
            data = json.loads(_http_get(NVD_API + "?" + urllib.parse.urlencode(q), headers, timeout=120, tries=6))
            total, vulns = int(data.get("totalResults", 0)), data.get("vulnerabilities", []) or []
            with intel.lock, intel.con:
                for item in vulns:
                    row, cpes = _nvd_rows(item)
                    if not row[0]: continue
                    if replace: intel.con.execute("DELETE FROM cpem WHERE cve=?", (row[0],))
                    intel.con.execute("INSERT OR REPLACE INTO cve VALUES(?,?,?,?,?)", row)
                    intel.con.executemany("INSERT INTO cpem VALUES(?,?,?,?,?,?,?,?)", cpes)
            idx += len(vulns); new_cves += len(vulns)
            if mode == "full": intel.set_meta("nvd_resume", idx)
            left = max(0, total - idx); eta = (left / 2000.0) * (delay + 1.2)
            _bar("NVD", min(idx, total), max(total, 1), f"{idx:,}/{total:,} CVEs · ETA {int(eta // 60)}m{int(eta % 60):02d}s")
            if not vulns or idx >= total: break
            time.sleep(delay)
    _bar_end()
    if mode == "full":
        intel.set_meta("nvd_last", intel.meta("nvd_build_start") or now.isoformat()); intel.set_meta("nvd_resume", None)
    else:
        intel.set_meta("nvd_last", now.isoformat())
    return f"{new_cves:,} CVE records {'downloaded' if mode == 'full' else 'refreshed'} ({mode})"

def update_db(intel, api_key="", ss_bin=None, msf_bin=None):
    """Refresh every source. Returns True when the NVD part (required) is complete."""
    steps = [("CISA KEV", lambda: update_kev(intel)), ("EPSS", lambda: update_epss(intel)),
             ("Exploit-DB", lambda: update_edb(intel, ss_bin)), ("Metasploit", lambda: update_msf(intel, msf_bin)),
             ("NVD", lambda: update_nvd(intel, api_key))]
    nvd_ok = False
    for name, fn in steps:
        info(f"updating {name} …")
        try:
            res = fn(); ok(f"{name}: {res}")
            if name == "NVD": nvd_ok = True
        except KeyboardInterrupt:
            _bar_end(); warn(f"{name}: interrupted — progress is saved; run --update-db again to resume.")
            intel._cache.clear(); intel._mcache.clear(); intel._counts = None
            return False
        except Exception as e:
            _bar_end(); warn(f"{name}: {type(e).__name__}: {e}")
    intel._cache.clear(); intel._mcache.clear(); intel._counts = None
    if nvd_ok or intel.ready():
        intel.set_meta("updated", datetime.now().isoformat(timespec="seconds"))
    return intel.ready()

# ---- runtime lookups: searchsploit --cve / msfconsole ------------------------
def ss_cve_lookup(ss, cves, limit=40):
    """searchsploit --cve for CVEs the local DB has no exploit for (parallel, capped)."""
    if not (ss and ss.available) or not cves: return {}
    def one(cve):
        try:
            proc = subprocess.run([ss.binary, "--cve", cve, "--json"], capture_output=True, text=True, timeout=25)
            data = json.loads(proc.stdout or "{}")
            return cve, [{"edb": str(r.get("EDB-ID", "")), "title": r.get("Title", ""), "type": r.get("Type", ""),
                          "platform": r.get("Platform", ""), "verified": ""} for r in (data.get("RESULTS_EXPLOIT") or [])[:3]]
        except Exception:
            return cve, []
    with ThreadPoolExecutor(max_workers=4) as ex:
        return {c: r for c, r in ex.map(one, cves[:limit]) if r}

def msf_cli_lookup(msf_bin, cves, limit=6):
    """Fallback when no module-metadata file exists: read-only `search cve:` via msfconsole."""
    out = {}
    for cve in cves[:limit]:
        try:
            proc = subprocess.run([msf_bin, "-q", "-x", f"search cve:{cve}; exit"], capture_output=True, text=True, timeout=150)
            mods = sorted(set(re.findall(r"\b((?:exploit|auxiliary)/[\w/.\-]+)", proc.stdout or "")))
            if mods: out[cve] = [{"module": m, "name": m.split("/")[-1], "rank": 0} for m in mods[:3]]
        except Exception:
            continue
    return out

# ---- the enrichment pass used by analyse() -----------------------------------
def enrich_with_intel(hosts, findings, exploits, intel, ss=None, max_per_service=25):
    groups = {}
    for h in hosts.values():
        for p in h.open_ports:
            ident = svc_ident(p)
            if ident: groups.setdefault(ident, []).append((h, p))
    matched = {}
    PROG.update(0.55, "Matching CVEs (CPE)", f"{len(groups)} unique services", force=True)
    for _gi, ident in enumerate(groups, 1):
        PROG.update(0.55 + 0.25 * _gi / max(1, len(groups)), "Matching CVEs (CPE)", f"service {_gi}/{len(groups)}")
        cves = intel.match(*ident[:3])
        if cves:
            infos = [intel.cve_info(c) for c in cves]
            for i in infos: i["priority"] = priority_of(i)
            infos.sort(key=lambda i: (i["priority"], -(i["epss"] or 0), -(i["cvss"] or 0), i["cve"]))
            matched[ident] = infos
    PROG.update(0.82, "Exploit lookups", "searchsploit --cve / Metasploit", force=True)
    # runtime exploit lookups for the CVEs that matter most and have no local exploit mapping
    wanted, seen = [], set()
    for infos in matched.values():
        for i in infos[:max_per_service]:
            if i["cve"] not in seen and not i["edb"] and (i["kev"] or (i["cvss"] or 0) >= 9): seen.add(i["cve"]); wanted.append(i["cve"])
    if wanted and ss is not None:
        for c, rows in ss_cve_lookup(ss, wanted).items(): intel.extra_edb[c] = rows
    if intel.counts().get("msf", 0) == 0:
        mb = shutil.which("msfconsole")
        if mb:
            todo = [c for c in seen if not intel.cve_info(c)["msf"]]
            for c, rows in msf_cli_lookup(mb, sorted(todo)).items(): intel.extra_msf[c] = rows
    have_f = {(f.host, f.port, c) for f in findings for c in CVE_RX.findall((f.cve or "") + " " + (f.title or ""))}
    have_x = {(e.host, e.port, e.title) for e in exploits}
    for _gi, (ident, targets) in enumerate(groups.items(), 1):
        PROG.update(0.86 + 0.10 * _gi / max(1, len(groups)), "Writing findings", f"service {_gi}/{len(groups)}")
        infos = matched.get(ident)
        if not infos: continue
        conf = ident[3]
        infos = [intel.cve_info(i["cve"]) | {"priority": i["priority"]} for i in infos]   # refresh with runtime lookups
        for i in infos: i["priority"] = priority_of(i)
        infos.sort(key=lambda i: (i["priority"], -(i["epss"] or 0), -(i["cvss"] or 0), i["cve"]))
        top, rest = infos[:max_per_service], infos[max_per_service:]
        for h, p in targets:
            label = f"{p.full_service or p.service} {p.version}".strip()
            for i in top:
                sev = "Critical" if i["kev"] else sev_from_cvss(i["cvss"])
                if (i["edb"] or i["msf"]) and sev == "Medium": sev = "High"
                tags = [i["priority"]] + (["KEV"] if i["kev"] else []) + \
                       ([f"EPSS {i['epss'] * 100:.0f}%"] if i["epss"] is not None else []) + \
                       ([f"CVSS {i['cvss']}"] if i["cvss"] is not None else []) + \
                       (["Metasploit"] if i["msf"] else []) + (["Exploit-DB"] if i["edb"] else [])
                if (h.ip, p.portid, i["cve"]) not in have_f:
                    have_f.add((h.ip, p.portid, i["cve"]))
                    findings.append(Finding(
                        host=h.ip, hostname=h.display_name, port=p.portid, protocol=p.protocol,
                        service=p.full_service or p.service, banner=p.banner, severity=sev,
                        category=f"Known CVE ({conf})",
                        title=f"{i['cve']} · {' · '.join(tags)} — {short_text(i['descr'], 110) or 'see NVD for details'}",
                        detail=((f"{full_text(i['descr'])} " if i["descr"] else "")
                                + f"{label} matches NVD affected-version data for {i['cve']} ({conf}). "
                                + (f"Listed in CISA KEV (known exploited{', ransomware use' if (i['kev'] or {}).get('ransomware') == 'Known' else ''}). " if i["kev"] else "")
                                + "Distros often back-port fixes without changing the banner — verify the exact package version before reporting."),
                        remediation="Upgrade to a fixed release or apply the vendor/distro patch; confirm with the package changelog.",
                        cve=i["cve"], reference=f"https://nvd.nist.gov/vuln/detail/{i['cve']}",
                        priority=i["priority"], confidence=conf))
                for e in i["edb"][:2]:
                    t = e["title"] or f"Exploit-DB {e['edb']}"
                    if (h.ip, p.portid, t) not in have_x:
                        have_x.add((h.ip, p.portid, t))
                        exploits.append(ExploitRef(host=h.ip, port=p.portid, service=p.full_service or p.service, title=t,
                            severity=sev, cve=i["cve"], source="Exploit-DB (local DB)", reference=f"EDB-ID {e['edb']}",
                            detail=f"{e.get('type', '')} · {e.get('platform', '')} — maps to {i['cve']}",
                            priority=i["priority"], confidence=conf))
                for m in i["msf"][:2]:
                    t = f"Metasploit: {m['name'] or m['module']}"
                    if (h.ip, p.portid, t) not in have_x:
                        have_x.add((h.ip, p.portid, t))
                        exploits.append(ExploitRef(host=h.ip, port=p.portid, service=p.full_service or p.service, title=t,
                            severity=sev, cve=i["cve"], source="Metasploit module", reference=m["module"],
                            detail=f"Module exists for {i['cve']} — presence only, nothing was run.",
                            priority=i["priority"], confidence=conf))
            if rest:
                findings.append(Finding(
                    host=h.ip, hostname=h.display_name, port=p.portid, protocol=p.protocol,
                    service=p.full_service or p.service, banner=p.banner, severity="Low",
                    category=f"Known CVE ({conf})", title=f"{len(rest)} more lower-priority CVEs match {label}",
                    detail="Not itemised to keep results readable: " + ", ".join(i["cve"] for i in rest[:40]) + (" …" if len(rest) > 40 else ""),
                    remediation="Patching to a current release clears these together.", priority="P4", confidence=conf))
    # tag the findings/exploits that already existed (built-in rules, NSE vulners) with priority + confidence
    def _best(text):
        best = None
        for c in CVE_RX.findall(text or ""):
            i = intel.cve_info(c)
            if not (i["in_nvd"] or i["kev"] or i["edb"] or i["msf"]): continue
            pr = priority_of(i)
            if best is None or pr < best[0]: best = (pr, i)
        return best
    for f in findings:
        if f.priority: continue
        b = _best((f.cve or "") + " " + (f.title or ""))
        if b:
            f.priority = b[0]; f.confidence = f.confidence or ("NSE script" if "NSE" in (f.category or "") else "Built-in rule")
            if b[1]["kev"] and SEV_RANK[f.severity] > SEV_RANK["Critical"]: f.severity = "Critical"
    for e in exploits:
        if e.priority: continue
        b = _best((e.cve or "") + " " + (e.title or ""))
        if b: e.priority = b[0]; e.confidence = e.confidence or ("NSE script" if "NSE" in (e.source or "") else "Built-in rule")
    # re-score hosts now that DB findings exist
    for ip, h in hosts.items():
        score = min(100, sum(SEV_WEIGHT[f.severity] for f in findings if f.host == ip))
        h.risk_score = score
        h.risk_level = ("Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 20
                        else "Low" if score > 0 else "Clean")

# ==========================================================================
# PRECHECK — verify prerequisites, print how to fix, or continue
# ==========================================================================
def detect_os():
    s = platform.system()
    if s == "Darwin": return "macos"
    if s == "Windows": return "windows"
    try: txt = Path("/etc/os-release").read_text().lower()
    except Exception: txt = ""
    if "kali" in txt: return "kali"
    if any(x in txt for x in ("ubuntu", "debian", "mint", "parrot", "pop!_os")): return "debian"
    if any(x in txt for x in ("arch", "manjaro", "endeavour")): return "arch"
    if any(x in txt for x in ("fedora", "rhel", "centos", "rocky", "alma")): return "redhat"
    return "linux"

_GIT_SS = ["sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb",
           "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit"]
_MSF_RAPID7 = ["curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/"
               "metasploit-framework-wrappers/msfupdate.erb > msfinstall",
               "chmod 755 msfinstall && sudo ./msfinstall"]
def install_cmds(tool, osid):
    if osid == "windows":
        return ["Windows: run this tool inside WSL2 (Kali is ideal):", "wsl --install -d kali-linux",
                "# then, inside Kali:  sudo apt update && sudo apt install -y exploitdb metasploit-framework"]
    if tool == "searchsploit":
        return {"kali": ["sudo apt update && sudo apt install -y exploitdb"],
                "debian": ["sudo apt update && sudo apt install -y exploitdb", "# if the package is unavailable:"] + _GIT_SS,
                "arch": ["sudo pacman -S --needed exploitdb"], "macos": ["brew install exploitdb"]}.get(osid, _GIT_SS)
    if tool == "msf":
        return {"kali": ["sudo apt update && sudo apt install -y metasploit-framework"],
                "arch": ["yay -S metasploit        # AUR  (or enable the BlackArch repo)"],
                "macos": ["brew install --cask metasploit"]}.get(osid, _MSF_RAPID7)
    return []

_ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")
def _vlen(s): return len(_ANSI_RX.sub("", s))

def _panel(title, lines, color="cyan", width=80):
    """Left-bar panel (no right border) so long, copy-pasteable commands never break the frame."""
    t = f" {title} "
    print(paint("╭─" + t + "─" * max(4, width - 3 - len(t)), color, bold=True))
    for ln in lines:
        print(paint("│", color, bold=True) + " " + ln)
    print(paint("╰" + "─" * (width - 1), color, bold=True))

def _ask(question, default_yes):
    if not (sys.stdin.isatty() and sys.stderr.isatty()): return None
    try: ans = input(question).strip().lower()
    except (EOFError, KeyboardInterrupt): print(); return None
    return default_yes if ans == "" else ans.startswith("y")

def run_precheck(args):
    """Returns (VulnIntel|None, exit_code). exit_code != 0 -> caller must stop."""
    osid = detect_os()
    script = os.path.basename(sys.argv[0] or "nmapilizer_v7.py")
    rows, fails = [], []          # rows: printable lines; fails: (name, [fix lines])
    def good(name, detail): rows.append(paint(" ✔ ", "green", bold=True) + paint(f"{name:<22}", bold=True) + paint(detail, dim=True))
    def bad(name, detail, fix): rows.append(paint(" ✘ ", "red", bold=True) + paint(f"{name:<22}", bold=True) + paint(detail, "red")); fails.append((name, fix))
    def meh(name, detail): rows.append(paint(" ⚠ ", "yellow", bold=True) + paint(f"{name:<22}", bold=True) + paint(detail, "yellow"))

    # 1) python
    pv = sys.version_info
    if pv >= (3, 9): good("Python", f"{pv.major}.{pv.minor}.{pv.micro}  ({platform.system()} · detected: {osid})")
    else: bad("Python", f"{pv.major}.{pv.minor} found — 3.9+ required", ["Install Python 3.9 or newer from your package manager / python.org"])
    # 2) searchsploit
    ss_arg = getattr(args, "searchsploit_path", "") or ""
    ss_bin = ss_arg if (ss_arg and os.path.exists(ss_arg)) else shutil.which("searchsploit")
    edb_csv = None
    if ss_bin:
        edb_csv = find_edb_csv(ss_bin)
        if edb_csv: good("searchsploit", f"{ss_bin}  · Exploit-DB data OK")
        else: meh("searchsploit", f"{ss_bin} found, but files_exploits.csv not located (will download; or run: searchsploit -u)")
    else:
        bad("searchsploit", "not found on PATH", install_cmds("searchsploit", osid) + ["searchsploit -u        # update Exploit-DB data afterwards"])
    # 3) metasploit
    msf_bin = shutil.which("msfconsole")
    if msf_bin:
        meta_p = find_msf_meta(msf_bin)
        good("Metasploit", f"{msf_bin}  · " + ("module metadata OK" if meta_p else "metadata file not found (msfconsole search fallback)"))
    else:
        bad("Metasploit", "msfconsole not found on PATH", install_cmds("msf", osid))
    # 4) local vulnerability DB
    dbp = default_db_path(getattr(args, "db", ""))
    intel = None
    try: intel = VulnIntel(dbp)
    except Exception as e:
        bad("Vulnerability DB", f"cannot open {dbp}: {e}", [f"Check permissions on {dbp.parent}, or choose another file with --db PATH"])
    db_issue = None
    if intel is not None:
        if intel.ready():
            c = intel.counts(); age = intel.age_days()
            detail = (f"{c['cve']:,} CVEs · {c['cpem']:,} CPE ranges · KEV {c['kev']:,} · EPSS {c['epss']:,} · "
                      f"EDB {c['edb']:,} · MSF {c['msf']:,}")
            good("Vulnerability DB", detail)
            if age is not None and age > DB_MAX_AGE_DAYS: db_issue = "stale"; meh("DB freshness", f"last updated {age:.0f} days ago (> {DB_MAX_AGE_DAYS})")
            else: good("DB freshness", f"updated {age:.1f} day(s) ago" if age is not None else "ok")
        else:
            db_issue = "missing"
            partial = "partially downloaded — can resume" if intel.meta("nvd_resume") else "not built yet"
            bad("Vulnerability DB", f"{partial}  ({dbp})", [f"python3 {script} --update-db"])

    _panel(f"NMAPILIZER {VERSION} · PRECHECK", [""] + rows + [""])

    if fails and any(n != "Vulnerability DB" for n, _ in fails):
        lines = [paint(" Missing prerequisites — install them, then run this script again.", "yellow", bold=True), ""]
        for name, fix in fails:
            if name == "Vulnerability DB": continue
            lines.append(paint(f" ▸ {name}", "cyan", bold=True))
            for cmd in fix:
                lines.append("     " + (paint(cmd, dim=True) if cmd.startswith("#") or cmd.endswith(":") else paint("$ ", "cyan") + cmd))
            lines.append("")
        if any(n == "Vulnerability DB" for n, _ in fails):
            lines += [paint(" ▸ Vulnerability DB (after the tools above are installed)", "cyan", bold=True),
                      "     " + paint("$ ", "cyan") + f"python3 {script} --update-db", ""]
        lines += [paint(" Tip: export NVD_API_KEY=<free key from nvd.nist.gov/developers> makes the first DB build ~8× faster.", dim=True),
                  paint(" Bypass (not recommended):  --skip-precheck", dim=True)]
        _panel("SETUP REQUIRED", lines, "yellow")
        return None, 3
    if fails and any(n == "Python" for n, _ in fails): return None, 3
    if intel is None: return None, 3

    # DB missing / incomplete -> offer to build it now
    if db_issue == "missing":
        if not _net_ok():
            _panel("SETUP REQUIRED", [paint(" The vulnerability DB must be built once and this machine is offline.", "yellow", bold=True), "",
                   paint(" ▸ Connect to the internet, then run:", "cyan", bold=True),
                   "     " + paint("$ ", "cyan") + f"python3 {script} --update-db", ""], "yellow")
            return None, 3
        want = _ask(paint("  Build the vulnerability DB now? First build downloads NVD (~15–25 min, ~2 min with NVD_API_KEY). [Y/n] ", "cyan", bold=True), True)
        if want is not True:
            _panel("SETUP REQUIRED", [paint(" Build the vulnerability DB, then run this script again:", "yellow", bold=True), "",
                   "     " + paint("$ ", "cyan") + f"python3 {script} --update-db", ""], "yellow")
            return None, 3
        key = getattr(args, "nvd_api_key", "") or os.environ.get("NVD_API_KEY", "")
        if not update_db(intel, key, ss_bin, msf_bin):
            _panel("DATABASE NOT READY", [paint(" The build did not finish. Re-run to resume where it stopped:", "red", bold=True), "",
                   "     " + paint("$ ", "cyan") + f"python3 {script} --update-db", ""], "red")
            return None, 3
    elif db_issue == "stale":
        if _net_ok():
            want = _ask(paint("  The DB is older than a week. Refresh it now (incremental, usually quick)? [y/N] ", "cyan", bold=True), False)
            if want:
                key = getattr(args, "nvd_api_key", "") or os.environ.get("NVD_API_KEY", "")
                update_db(intel, key, ss_bin, msf_bin)
        else:
            warn("DB is stale and this machine is offline — continuing with existing data.")
    # (re)load Metasploit module metadata when it changed since the last load — cheap, local
    try:
        mp = find_msf_meta(msf_bin)
        if mp and intel.meta("msf_mtime") != str(int(mp.stat().st_mtime)):
            update_msf(intel, msf_bin); intel.set_meta("msf_mtime", int(mp.stat().st_mtime)); intel._counts = None
    except Exception:
        pass
    print(paint("  ✔ All prerequisites OK — starting Nmapilizer", "green", bold=True) + "\n")
    return intel, 0

def cmd_update_db(args):
    dbp = default_db_path(getattr(args, "db", ""))
    print(paint(f"\n  Nmapilizer {VERSION} — vulnerability database update", "cyan", bold=True))
    print(paint(f"  database file: {dbp}", dim=True))
    if not _net_ok():
        warn("No internet connection (cannot reach services.nvd.nist.gov:443)."); return 3
    ss_bin = (getattr(args, "searchsploit_path", "") or shutil.which("searchsploit"))
    msf_bin = shutil.which("msfconsole")
    key = getattr(args, "nvd_api_key", "") or os.environ.get("NVD_API_KEY", "")
    if not key: info("No NVD_API_KEY set — NVD is rate-limited (≈6s per 2,000 CVEs). A free key makes this ~8× faster.")
    intel = VulnIntel(dbp)
    good = update_db(intel, key, ss_bin, msf_bin)
    s = intel.summary()
    _panel("DATABASE " + ("READY" if good else "INCOMPLETE"), [
        "", f" CVEs {s['cves']:,}   CPE ranges {s['cpe_rows']:,}   KEV {s['kev']:,}   EPSS {s['epss']:,}",
        f" Exploit-DB {s['edb']:,}   Metasploit {s['msf']:,}", f" file: {s['path']}", ""], "green" if good else "red")
    return 0 if good else 1

def open_intel_quiet(args):
    """--skip-precheck path: use the DB if it is usable, never prompt, never exit."""
    try:
        p = default_db_path(getattr(args, "db", ""))
        if not p.exists(): return None
        i = VulnIntel(p)
        return i if i.ready() else None
    except Exception:
        return None


def print_author_banner():
    """Author / project details shown in the terminal at every launch."""
    bar = paint("  │", "cyan")
    print(paint("  ┌" + "─" * 70, "cyan"))
    print(bar + paint(f"  Nmapilizer {VERSION}", "cyan", bold=True) + paint("  ·  Nmap scan analysis, CVE & exploit triage", dim=True))
    print(bar + paint("  Author     ", bold=True) + paint(AUTHOR_NAME, "magenta", bold=True))
    for n, u in AUTHOR_LINKS:
        print(bar + paint(f"  {n:<10} ", bold=True) + paint(u, "blue"))
    print(paint("  └" + "─" * 70, "cyan"))

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nmapilizer", description="Nmapilizer v7.1 by @BudSec (github.com/buddysecurity) — visualise & analyse Nmap .xml/.nmap/.gnmap output: flag weak/outdated services, find known exploits, colourised CLI, animated ASCII art.",
        epilog="Examples:\n"
               "  %(prog)s scan.xml scan.nmap scan.gnmap\n"
               "  %(prog)s -i scans/ --csv                      # + standalone CSV export\n"
               "  %(prog)s -i scans/ --csv-only                 # CSVs only, no HTML\n"
               "  %(prog)s -i scans/ --format html --theme midnight --classification CONFIDENTIAL\n"
               "  %(prog)s -i scans/ --animate                  # live animated ASCII art while analysing\n"
               "  %(prog)s -i scans/ --fake-run                 # play the art + 10s timer first (fake run)\n"
               "  %(prog)s -i scans/ --serve --watch scans/",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="*", help="Nmap .xml/.nmap/.gnmap files, directories, or globs")
    ap.add_argument("-i", "--input", action="append", default=[], help="Input file/dir/glob (repeatable)")
    ap.add_argument("-o", "--output", default=".", help="Parent folder for outputs (default: current dir)")
    ap.add_argument("--report-dir", default="", help="Exact output folder name (overrides auto DDMMYYYY_XXX name)")
    ap.add_argument("--title", default="Nmapilizer Report", help="Report title")
    # --- output formats / CSV ---
    ap.add_argument("--format", action="append", default=[], metavar="FMT",
                    help="Output format(s): html, csv, json, txt, all — repeatable or comma-separated (default: all)")
    ap.add_argument("--csv", action="store_true", help="Export CSV files (hosts/ports/findings/exploits) — into the report folder, plus --csv-dir if given")
    ap.add_argument("--csv-only", action="store_true", help="Export ONLY CSV files (no HTML/JSON/TXT report)")
    ap.add_argument("--csv-dir", default="", help="Also/only write CSV files to this directory")
    ap.add_argument("--csv-delimiter", default="comma", help="CSV delimiter: comma, semicolon, tab, pipe, or a single character (default comma)")
    ap.add_argument("--csv-prefix", default="", help="Prefix for CSV filenames, e.g. acme- -> acme-hosts.csv")
    # --- colour / terminal ---
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="Colourise CLI output (default auto = only on a terminal; honours NO_COLOR)")
    ap.add_argument("--no-color", action="store_true", help="Disable CLI colours (same as --color never)")
    ap.add_argument("--print-results", action="store_true", help="Print the colourised host-risk table + top findings to the terminal")
    ap.add_argument("--top", type=int, default=10, help="How many findings the terminal summary prints (default 10)")
    # --- ASCII art / animation ---
    ap.add_argument("--animate", "--ascii-art", action="store_true", dest="animate", default=None,
                    help="Force the live animated ASCII art ON (default: auto — on when running in a terminal)")
    ap.add_argument("--no-animate", "--no-art", action="store_false", dest="animate",
                    help="Turn the animated ASCII art OFF (overrides the on-by-default terminal behaviour)")
    ap.add_argument("--animation-style", choices=["radar", "wave", "matrix"], default="radar", help="ASCII art animation style (default radar)")
    ap.add_argument("--fake-run", action="store_true", help="Before analysing, fake a run: play the animated ASCII art with a timer for --fake-seconds")
    ap.add_argument("--fake-seconds", type=float, default=10.0, help="Fake-run duration in seconds (default 10)")
    # --- customisation ---
    ap.add_argument("--theme", choices=["dark", "light", "midnight", "forest", "solar"], default="", help="HTML report theme")
    ap.add_argument("--accent", default="", help="Accent colour override, e.g. '#ff0066'")
    ap.add_argument("--company", default="", help="Company/client name shown on every report page")
    ap.add_argument("--author", default="", help="Report 'Prepared by' name shown in the top banner (tool credit @BudSec is always in the footer)")
    ap.add_argument("--classification", default="", help="Classification banner on every report page, e.g. 'CONFIDENTIAL — INTERNAL USE'")
    ap.add_argument("--config", default="", help="JSON config file: any of theme/accent/company/author/classification/color/fake_seconds/animation_style as defaults")
    ap.add_argument("--custom-rules", default="", help="JSON file with your own dangerous_ports / outdated / exploits / highlights rules")
    ap.add_argument("--highlight", action="append", default=[], metavar="KEYWORD", help="Flag any banner containing KEYWORD (repeatable)")
    ap.add_argument("--highlight-severity", choices=SEVERITIES, default="Medium", help="Severity for --highlight matches (default Medium)")
    ap.add_argument("--include-host", action="append", default=[], help="Only include host IP/hostname/CIDR (repeatable)")
    ap.add_argument("--exclude-host", action="append", default=[], help="Exclude host IP/hostname/CIDR (repeatable)")
    ap.add_argument("--exclude-port", action="append", default=[], help="Exclude port(s): 23 or 8000-9000 or 21,23 (repeatable)")
    ap.add_argument("--show-closed", action="store_true", help="Include closed/filtered ports in ports/host pages")
    ap.add_argument("--sort-hosts", choices=["risk", "ip", "hostname", "ports"], default="risk", help="Host ordering in hosts.html (default risk)")
    ap.add_argument("--min-risk", type=int, default=0, help="Only report hosts with risk score >= this (0-100)")
    # --- serve ---
    ap.add_argument("--serve", action="store_true", help="Start the live 1-page web dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="Dashboard bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8080, help="Dashboard port (default 8080)")
    ap.add_argument("--watch", action="append", default=[], help="Directory to watch for new/changed scan files while serving (repeatable)")
    ap.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard")
    ap.add_argument("--no-report", action="store_true", help="With --serve, skip writing the static report bundle")
    ap.add_argument("--no-searchsploit", action="store_true", help="Skip local Exploit-DB lookups (built-in DB + NSE CVEs still run)")
    ap.add_argument("--searchsploit-path", default="", help="Path to the local exploit-search binary, if it is not on PATH")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="Info", help="Only include findings at/above this severity")
    ap.add_argument("--quiet", action="store_true", help="Less console output")
    ap.add_argument("--db", default="", help="Path of the local vulnerability database (default ~/.nmapilizer/vulndb.sqlite, or $NMAPILIZER_DB)")
    ap.add_argument("--update-db", action="store_true", help="Build / refresh the local vulnerability DB (NVD, CISA KEV, EPSS, Exploit-DB, Metasploit) and exit")
    ap.add_argument("--nvd-api-key", default="", help="Free NVD API key (or set NVD_API_KEY) — makes the first DB build ~8x faster")
    ap.add_argument("--skip-precheck", action="store_true", help="Bypass the startup prerequisite check (not recommended)")
    ap.add_argument("--max-cves-per-service", type=int, default=25, help="Itemise at most N highest-priority CVEs per detected service (default 25)")
    ap.add_argument("--version", action="version", version=f"Nmapilizer {VERSION} — by {AUTHOR_NAME} · github.com/buddysecurity")
    args = ap.parse_args(argv)

    # config file = defaults; explicit CLI values win
    cfg = load_config_file(args.config) if args.config else {}
    def cfgd(key, cli_val, default=""):
        return cli_val if cli_val not in ("", None, default) else cfg.get(key, cli_val if cli_val != "" else default)
    theme = cfgd("theme", args.theme, "") or "midnight"
    accent = cfgd("accent", args.accent); company = cfgd("company", args.company)
    author = cfgd("author", args.author); classification = cfgd("classification", args.classification)
    if not args.fake_run and cfg.get("fake_run"): args.fake_run = True
    if cfg.get("fake_seconds") and args.fake_seconds == 10.0: args.fake_seconds = float(cfg["fake_seconds"])
    if cfg.get("animation_style") and args.animation_style == "radar": args.animation_style = cfg["animation_style"]
    color_mode = "never" if args.no_color else (cfg.get("color", args.color) if args.color == "auto" and cfg.get("color") else args.color)
    setup_color(color_mode)

    print_author_banner()
    # v7: prerequisites first — nothing else runs until they pass
    global INTEL, MAX_CVES_PER_SERVICE
    MAX_CVES_PER_SERVICE = max(1, args.max_cves_per_service)
    if args.update_db:
        return cmd_update_db(args)
    if args.skip_precheck:
        INTEL = open_intel_quiet(args)
        warn("--skip-precheck: prerequisite checks bypassed" + ("" if INTEL else " · no usable vulnerability DB → CPE/CVE database matching is OFF"))
    else:
        INTEL, _code = run_precheck(args)
        if _code: return _code

    # formats
    formats = set()
    for f in args.format:
        formats.update(x.strip().lower() for x in f.split(",") if x.strip())
    if not formats or "all" in formats: formats = {"html", "csv", "json", "txt"}
    if args.csv: formats.add("csv")
    if args.csv_only: formats = {"csv"}
    report_opts = {"theme": theme, "accent": accent, "company": company, "author": author,
                   "classification": classification, "show_closed": args.show_closed,
                   "sort_hosts": args.sort_hosts}

    # custom rules / highlights
    if args.custom_rules:
        n = load_custom_rules(args.custom_rules)
        if not args.quiet: info(f"custom rules loaded: {n} rule(s) from {args.custom_rules}")
    for kw in args.highlight: HIGHLIGHTS.append((kw, args.highlight_severity))

    # fake run first if asked (art + timer, exactly --fake-seconds)
    if args.fake_run:
        run_fake_animation(args.fake_seconds, args.animation_style)

    # v2.1 best-experience default: art is ON automatically in a terminal
    # (unless --quiet or --no-animate); --animate forces it even when piped.
    want_anim = args.animate if args.animate is not None else (sys.stderr.isatty() and not args.quiet)
    anim = AnimatedArt(style=args.animation_style) if want_anim else None
    if anim:
        anim.status = "Parsing & analysing scan files…"; anim.start()
    try:
        inputs = list(args.inputs) + list(args.input)
        files = collect_input_files(inputs)
        state = LiveState(use_searchsploit=not args.no_searchsploit)
        if args.searchsploit_path: state.ss = Searchsploit(args.searchsploit_path)
        errors = []
        excl_ports = parse_port_set(args.exclude_port)
        for f in files:
            try:
                n = state.add_file(f, defer=True)
                if anim: anim.status = f"Analysed {f.name} — {len(state.hosts)} host(s) so far…"
                if not args.quiet and not anim: ok(f"{f} → {n} host(s)")
            except Exception as e:
                errors.append(str(e)); warn(str(e))
        # host/port filters (customisation)
        for ip in list(state.hosts):
            h = state.hosts[ip]
            if not host_selected(ip, h.display_name, args.include_host, args.exclude_host):
                del state.hosts[ip]; continue
            for key in [k for k in h.ports if k[1] in excl_ports]: del h.ports[key]
        if state.hosts:
            if anim: anim.status = "Analysing hosts, matching CVEs and exploits…"
            PROG.cli = bool(not args.serve and not anim and not args.quiet)
            state._reanalyse()
        if errors and not state.hosts and not args.serve:
            warn("No valid Nmap output could be parsed. Export with: nmap -sV -oX scan.xml / -oN scan.nmap / -oG scan.gnmap <target>")
            return 2

        if args.serve:
            state.report_base = Path(args.output)
            state.report_title = args.title
            state.report_opts = report_opts
            if not args.no_report and state.hosts:
                out = Path(args.report_dir) if args.report_dir else next_report_dir(Path(args.output))
                ds = generate_report(state.hosts, _filter_sev(state.findings, args.min_severity),
                                     state.exploits, state.metas, out, args.title, report_opts)
                prune_formats(out, formats)
                if args.csv_dir: export_csvs(ds, Path(args.csv_dir), csv_delimiter(args.csv_delimiter), args.csv_prefix)
                if not args.quiet: ok(f"Static report also written → {out}/")
            if anim: anim.stop(); anim = None
            serve(state, args.host, args.port, [Path(w) for w in args.watch], not args.no_browser)
            return 0
        if not state.hosts:
            ap.print_usage(sys.stderr)
            warn("Give me at least one .xml/.nmap/.gnmap file, or use --serve and import files in the browser.")
            return 2
        out = Path(args.report_dir) if args.report_dir else next_report_dir(Path(args.output))
        findings = _filter_sev(state.findings, args.min_severity)
        if formats == {"csv"}:
            ds = build_dataset(state.hosts, findings, state.exploits, state.metas)
            written = export_csvs(ds, out, csv_delimiter(args.csv_delimiter), args.csv_prefix)
            if args.csv_dir: written += export_csvs(ds, Path(args.csv_dir), csv_delimiter(args.csv_delimiter), args.csv_prefix)
        else:
            ds = generate_report(state.hosts, findings, state.exploits, state.metas, out, args.title, report_opts)
            prune_formats(out, formats)
            written = []
            if args.csv_dir and "csv" in formats:
                written = export_csvs(ds, Path(args.csv_dir), csv_delimiter(args.csv_delimiter), args.csv_prefix)
        # min-risk filter note (applied to terminal summary view)
        if args.min_risk:
            kept = [h for h in ds["hosts"] if h["risk_score"] >= args.min_risk]
            if not args.quiet: info(f"--min-risk {args.min_risk}: {len(kept)}/{len(ds['hosts'])} host(s) at/above threshold (full data stays in data.json)")
    finally:
        if anim: anim.stop()
    if args.print_results or COLOR_ENABLED:
        print_cli_summary(ds, args.top)
    else:
        t = ds["totals"]
        print(f"Hosts: {t['hosts']} · Findings: {t['findings']} · Exploits: {t['exploits']}")
    ok(f"Output → {out}/  formats: {', '.join(sorted(formats))}")
    if "html" in formats and formats != {"csv"}: print(f"    Open: {out}/index.html")
    if "csv" in formats:
        csvs = [str(p) for p in (written or sorted(out.glob('*.csv')))]
        print("    CSV: " + (", ".join(csvs) if csvs else f"{out}/*.csv"))
    return 0

def _filter_sev(findings, min_sev):
    return [f for f in findings if SEV_RANK[f.severity] <= SEV_RANK[min_sev]]

if __name__ == "__main__":
    raise SystemExit(main())
