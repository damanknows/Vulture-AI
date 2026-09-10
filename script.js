/* =========================================
   VULNSCAN — APP LOGIC
   Scan engine + CVE matching + Dashboard + Chat
========================================= */

(function () {
  'use strict';

  // ==========================================================
  // 1. CVE DATABASE (curated subset of real CVEs for demo)
  // ==========================================================
  // Each entry is keyed by (vendor, product, versionPrefix).
  // versionPrefix matches if the detected version startsWith.
  const CVE_DB = [
    // Apache httpd
    { vendor: 'apache', product: 'http_server', versionPrefix: '2.4.49', cves: [
      { id: 'CVE-2021-41773', cvss: 9.8, severity: 'CRITICAL', desc: 'Path traversal and remote code execution in Apache HTTP Server 2.4.49 via crafted URI.', kev: true, cpe: 'cpe:2.3:a:apache:http_server:2.4.49' },
    ]},
    { vendor: 'apache', product: 'http_server', versionPrefix: '2.4.50', cves: [
      { id: 'CVE-2021-42013', cvss: 9.8, severity: 'CRITICAL', desc: 'Patch bypass for CVE-2021-41773 in Apache 2.4.50 — same path-traversal/RCE flaw.', kev: true, cpe: 'cpe:2.3:a:apache:http_server:2.4.50' },
    ]},
    { vendor: 'apache', product: 'http_server', versionPrefix: '2.4.41', cves: [
      { id: 'CVE-2020-11984', cvss: 7.5, severity: 'HIGH', desc: 'Mod_proxy_ftp wildcard use may allow SSRF/RCE.', kev: false, cpe: 'cpe:2.3:a:apache:http_server:2.4.41' },
    ]},

    // nginx
    { vendor: 'nginx', product: 'nginx', versionPrefix: '1.18.0', cves: [
      { id: 'CVE-2021-23017', cvss: 7.7, severity: 'HIGH', desc: '1-byte memory overwrite in resolver via crafted DNS response.', kev: false, cpe: 'cpe:2.3:a:f5:nginx:1.18.0' },
    ]},
    { vendor: 'nginx', product: 'nginx', versionPrefix: '1.16.1', cves: [
      { id: 'CVE-2020-12440', cvss: 6.4, severity: 'MEDIUM', desc: 'Memory disclosure in nginx HTTP/3 implementation.', kev: false, cpe: 'cpe:2.3:a:f5:nginx:1.16.1' },
    ]},

    // OpenSSH
    { vendor: 'openbsd', product: 'openssh', versionPrefix: '7.4', cves: [
      { id: 'CVE-2018-15473', cvss: 5.3, severity: 'MEDIUM', desc: 'User enumeration vulnerability in OpenSSH due to timing side-channel.', kev: false, cpe: 'cpe:2.3:a:openbsd:openssh:7.4' },
    ]},
    { vendor: 'openbsd', product: 'openssh', versionPrefix: '8.5', cves: [
      { id: 'CVE-2021-41617', cvss: 7.0, severity: 'HIGH', desc: 'Privilege escalation via authorized_keys command injection.', kev: false, cpe: 'cpe:2.3:a:openbsd:openssh:8.5' },
    ]},
    { vendor: 'openbsd', product: 'openssh', versionPrefix: '9.1', cves: [
      { id: 'CVE-2023-38408', cvss: 9.8, severity: 'CRITICAL', desc: 'Remote code execution via forwarded ssh-agent socket.', kev: true, cpe: 'cpe:2.3:a:openbsd:openssh:9.1' },
    ]},

    // MySQL / MariaDB
    { vendor: 'oracle', product: 'mysql', versionPrefix: '5.7.33', cves: [
      { id: 'CVE-2022-21417', cvss: 6.5, severity: 'MEDIUM', desc: 'Easily exploitable vulnerability in MySQL Server Optimizer component.', kev: false, cpe: 'cpe:2.3:a:oracle:mysql:5.7.33' },
    ]},
    { vendor: 'oracle', product: 'mysql', versionPrefix: '8.0.27', cves: [
      { id: 'CVE-2022-1292', cvss: 9.8, severity: 'CRITICAL', desc: 'OpenSSL c_rehash script command injection (bundled with MySQL 8.0.27 on some platforms).', kev: true, cpe: 'cpe:2.3:a:oracle:mysql:8.0.27' },
    ]},
    { vendor: 'oracle', product: 'mysql', versionPrefix: '5.6.51', cves: [
      { id: 'CVE-2022-21540', cvss: 7.2, severity: 'HIGH', desc: 'Vulnerability in MySQL Server InnoDB. Hard to exploit, high impact.', kev: false, cpe: 'cpe:2.3:a:oracle:mysql:5.6.51' },
    ]},

    // PostgreSQL
    { vendor: 'postgresql', product: 'postgresql', versionPrefix: '13.3', cves: [
      { id: 'CVE-2021-32027', cvss: 7.5, severity: 'HIGH', desc: 'Buffer overrun in postgres array modification.', kev: false, cpe: 'cpe:2.3:a:postgresql:postgresql:13.3' },
    ]},
    { vendor: 'postgresql', product: 'postgresql', versionPrefix: '14.2', cves: [
      { id: 'CVE-2022-1552', cvss: 8.8, severity: 'HIGH', desc: 'Privilege escalation via pg_signal_backend role misuse.', kev: false, cpe: 'cpe:2.3:a:postgresql:postgresql:14.2' },
    ]},
    { vendor: 'postgresql', product: 'postgresql', versionPrefix: '15.1', cves: [
      { id: 'CVE-2023-2454', cvss: 7.2, severity: 'HIGH', desc: 'CREATE OR REPLACE permission escalation.', kev: false, cpe: 'cpe:2.3:a:postgresql:postgresql:15.1' },
    ]},

    // Redis
    { vendor: 'redis', product: 'redis', versionPrefix: '6.0.9', cves: [
      { id: 'CVE-2021-32625', cvss: 6.5, severity: 'MEDIUM', desc: 'Integer overflow in STRALGO LCS leading to memory corruption.', kev: false, cpe: 'cpe:2.3:a:redis:redis:6.0.9' },
    ]},
    { vendor: 'redis', product: 'redis', versionPrefix: '7.0.8', cves: [
      { id: 'CVE-2023-28856', cvss: 7.5, severity: 'HIGH', desc: 'Specially crafted Lua script may lead to denial of service.', kev: false, cpe: 'cpe:2.3:a:redis:redis:7.0.8' },
    ]},

    // ProFTPD
    { vendor: 'proftpd', product: 'proftpd', versionPrefix: '1.3.5', cves: [
      { id: 'CVE-2015-3306', cvss: 10.0, severity: 'CRITICAL', desc: 'Mod_copy unauthenticated arbitrary file copy (RCE chain).', kev: true, cpe: 'cpe:2.3:a:proftpd:proftpd:1.3.5' },
    ]},

    // Microsoft IIS
    { vendor: 'microsoft', product: 'iis', versionPrefix: '10.0', cves: [
      { id: 'CVE-2021-31166', cvss: 9.8, severity: 'CRITICAL', desc: 'HTTP Protocol Stack (http.sys) RCE — wormable.', kev: true, cpe: 'cpe:2.3:a:microsoft:iis:10.0' },
    ]},

    // Samba
    { vendor: 'samba', product: 'samba', versionPrefix: '4.13.13', cves: [
      { id: 'CVE-2021-44142', cvss: 9.9, severity: 'CRITICAL', desc: 'Out-of-bounds read/write in vfs_fruit module → RCE.', kev: true, cpe: 'cpe:2.3:a:samba:samba:4.13.13' },
    ]},

    // Tomcat
    { vendor: 'apache', product: 'tomcat', versionPrefix: '9.0.50', cves: [
      { id: 'CVE-2022-22965', cvss: 9.8, severity: 'CRITICAL', desc: 'Spring4Shell — RCE via data binding in Spring MVC on Tomcat.', kev: true, cpe: 'cpe:2.3:a:apache:tomcat:9.0.50' },
    ]},
    { vendor: 'apache', product: 'tomcat', versionPrefix: '10.0.4', cves: [
      { id: 'CVE-2021-25329', cvss: 7.5, severity: 'HIGH', desc: 'Session persistence DoS in Tomcat.', kev: false, cpe: 'cpe:2.3:a:apache:tomcat:10.0.4' },
    ]},

    // WordPress
    { vendor: 'wordpress', product: 'wordpress', versionPrefix: '5.8', cves: [
      { id: 'CVE-2021-29447', cvss: 7.5, severity: 'HIGH', desc: 'XXE in media parsing — file read.', kev: false, cpe: 'cpe:2.3:a:wordpress:wordpress:5.8' },
    ]},
    { vendor: 'wordpress', product: 'wordpress', versionPrefix: '6.0', cves: [
      { id: 'CVE-2022-21661', cvss: 9.8, severity: 'CRITICAL', desc: 'SQL injection via WP_Query.', kev: false, cpe: 'cpe:2.3:a:wordpress:wordpress:6.0' },
    ]},

    // Jenkins
    { vendor: 'jenkins', product: 'jenkins', versionPrefix: '2.303.3', cves: [
      { id: 'CVE-2022-26134', cvss: 9.8, severity: 'CRITICAL', desc: 'Unauthenticated RCE via Groovy AST transforms.', kev: true, cpe: 'cpe:2.3:a:jenkins:jenkins:2.303.3' },
    ]},

    // Elasticsearch
    { vendor: 'elastic', product: 'elasticsearch', versionPrefix: '7.16.3', cves: [
      { id: 'CVE-2022-23710', cvss: 7.5, severity: 'HIGH', desc: 'Heap OOB read leading to info disclosure.', kev: false, cpe: 'cpe:2.3:a:elastic:elasticsearch:7.16.3' },
    ]},

    // MongoDB
    { vendor: 'mongodb', product: 'mongodb', versionPrefix: '4.4.6', cves: [
      { id: 'CVE-2021-32040', cvss: 7.2, severity: 'HIGH', desc: 'Improper validation of array indexes leading to crashes.', kev: false, cpe: 'cpe:2.3:a:mongodb:mongodb:4.4.6' },
    ]},

    // Dovecot
    { vendor: 'dovecot', product: 'dovecot', versionPrefix: '2.3.13', cves: [
      { id: 'CVE-2021-33558', cvss: 7.5, severity: 'HIGH', desc: 'DoS via large email message with many recipients.', kev: false, cpe: 'cpe:2.3:a:dovecot:dovecot:2.3.13' },
    ]},

    // Exim
    { vendor: 'exim', product: 'exim', versionPrefix: '4.94.2', cves: [
      { id: 'CVE-2019-15846', cvss: 9.8, severity: 'CRITICAL', desc: 'RCE via sender address buffer overflow.', kev: false, cpe: 'cpe:2.3:a:exim:exim:4.94.2' },
    ]},

    // Bind9
    { vendor: 'isc', product: 'bind', versionPrefix: '9.16.1', cves: [
      { id: 'CVE-2020-8625', cvss: 8.6, severity: 'HIGH', desc: 'Buffer overflow in tsig-key handling.', kev: false, cpe: 'cpe:2.3:a:isc:bind:9.16.1' },
    ]},
  ];

  // Service fingerprints (banner -> vendor/product/version detection rules)
  const SERVICE_FINGERPRINTS = {
    'SSH': [
      { match: /^SSH-2\.0-OpenSSH_(\d+\.\d+(?:\.\d+)?)/, vendor: 'openbsd', product: 'openssh', versionIdx: 1 },
      { match: /^SSH-2\.0-dropbear_([\d.]+)/, vendor: 'dropbear', product: 'dropbear', versionIdx: 1 },
    ],
    'HTTP': [
      { match: /Apache\/(\d+\.\d+\.\d+)/i, vendor: 'apache', product: 'http_server', versionIdx: 1 },
      { match: /nginx\/(\d+\.\d+\.\d+)/i, vendor: 'nginx', product: 'nginx', versionIdx: 1 },
      { match: /Microsoft-IIS\/(\d+\.\d+)/i, vendor: 'microsoft', product: 'iis', versionIdx: 1 },
    ],
    'HTTPS': [
      { match: /Apache\/(\d+\.\d+\.\d+)/i, vendor: 'apache', product: 'http_server', versionIdx: 1 },
      { match: /nginx\/(\d+\.\d+\.\d+)/i, vendor: 'nginx', product: 'nginx', versionIdx: 1 },
      { match: /Microsoft-IIS\/(\d+\.\d+)/i, vendor: 'microsoft', product: 'iis', versionIdx: 1 },
    ],
    'MYSQL': [
      { match: /^(\d+\.\d+\.\d+)/, vendor: 'oracle', product: 'mysql', versionIdx: 1 },
    ],
    'POSTGRES': [
      { match: /PostgreSQL (\d+\.\d+\.\d+)/i, vendor: 'postgresql', product: 'postgresql', versionIdx: 1 },
    ],
    'REDIS': [
      { match: /redis_version:(\d+\.\d+\.\d+)/i, vendor: 'redis', product: 'redis', versionIdx: 1 },
    ],
    'FTP': [
      { match: /ProFTPD (\d+\.\d+\.\d+)/i, vendor: 'proftpd', product: 'proftpd', versionIdx: 1 },
      { match: /vsftpd (\d+\.\d+\.\d+)/i, vendor: 'vsftpd', product: 'vsftpd', versionIdx: 1 },
    ],
    'SMTP': [
      { match: /Exim (\d+\.\d+\.\d+)/i, vendor: 'exim', product: 'exim', versionIdx: 1 },
      { match: /Postfix/i, vendor: 'postfix', product: 'postfix', versionIdx: 0 },
    ],
    'TOMCAT': [
      { match: /Apache-Coyote\/(\d+\.\d+)/i, vendor: 'apache', product: 'tomcat', versionIdx: 1 },
    ],
    'WORDPRESS': [
      { match: /WordPress (\d+\.\d+(?:\.\d+)?)/i, vendor: 'wordpress', product: 'wordpress', versionIdx: 1 },
    ],
    'JENKINS': [
      { match: /Jenkins\/(\d+\.\d+\.\d+)/i, vendor: 'jenkins', product: 'jenkins', versionIdx: 1 },
    ],
    'ELASTICSEARCH': [
      { match: /"number"\s*:\s*"(\d+\.\d+\.\d+)"/i, vendor: 'elastic', product: 'elasticsearch', versionIdx: 1 },
    ],
    'MONGODB': [
      { match: /"version"\s*:\s*"(\d+\.\d+\.\d+)"/i, vendor: 'mongodb', product: 'mongodb', versionIdx: 1 },
    ],
    'DNS': [
      { match: /BIND (\d+\.\d+\.\d+)/i, vendor: 'isc', product: 'bind', versionIdx: 1 },
    ],
    'SAMBA': [
      { match: /Samba (\d+\.\d+\.\d+)/i, vendor: 'samba', product: 'samba', versionIdx: 1 },
    ],
    'IMAP': [
      { match: /Dovecot ready/i, vendor: 'dovecot', product: 'dovecot', versionIdx: 0 },
    ],
  };

  // Port-to-service map
  const PORT_SERVICES = {
    21:   { name: 'FTP',           severity: 'high',     protocol: 'tcp', desc: 'File Transfer Protocol' },
    22:   { name: 'SSH',           severity: 'info',     protocol: 'tcp', desc: 'Secure Shell' },
    23:   { name: 'Telnet',        severity: 'critical', protocol: 'tcp', desc: 'Unencrypted remote access' },
    25:   { name: 'SMTP',          severity: 'medium',   protocol: 'tcp', desc: 'Mail submission' },
    53:   { name: 'DNS',           severity: 'info',     protocol: 'udp', desc: 'Domain Name System' },
    80:   { name: 'HTTP',          severity: 'medium',   protocol: 'tcp', desc: 'Web server' },
    110:  { name: 'POP3',          severity: 'medium',   protocol: 'tcp', desc: 'Mail retrieval' },
    139:  { name: 'NetBIOS',       severity: 'high',     protocol: 'tcp', desc: 'Windows netbios' },
    143:  { name: 'IMAP',          severity: 'medium',   protocol: 'tcp', desc: 'Mail retrieval' },
    443:  { name: 'HTTPS',         severity: 'low',      protocol: 'tcp', desc: 'TLS web server' },
    445:  { name: 'SMB',           severity: 'high',     protocol: 'tcp', desc: 'Server message block' },
    465:  { name: 'SMTPS',         severity: 'low',      protocol: 'tcp', desc: 'SMTP over TLS' },
    587:  { name: 'Submission',    severity: 'low',      protocol: 'tcp', desc: 'Mail submission' },
    993:  { name: 'IMAPS',         severity: 'low',      protocol: 'tcp', desc: 'IMAP over TLS' },
    995:  { name: 'POP3S',         severity: 'low',      protocol: 'tcp', desc: 'POP3 over TLS' },
    1433: { name: 'MSSQL',         severity: 'high',     protocol: 'tcp', desc: 'Microsoft SQL Server' },
    1521: { name: 'OracleDB',      severity: 'high',     protocol: 'tcp', desc: 'Oracle DB' },
    3306: { name: 'MYSQL',         severity: 'high',     protocol: 'tcp', desc: 'MySQL' },
    3389: { name: 'RDP',           severity: 'critical', protocol: 'tcp', desc: 'Remote Desktop' },
    5432: { name: 'POSTGRES',      severity: 'high',     protocol: 'tcp', desc: 'PostgreSQL' },
    5900: { name: 'VNC',           severity: 'high',     protocol: 'tcp', desc: 'Virtual Network Computing' },
    6379: { name: 'REDIS',         severity: 'high',     protocol: 'tcp', desc: 'Redis cache' },
    8000: { name: 'HTTP-ALT',      severity: 'medium',   protocol: 'tcp', desc: 'HTTP alternate' },
    8080: { name: 'TOMCAT',        severity: 'high',     protocol: 'tcp', desc: 'Apache Tomcat / HTTP proxy' },
    8443: { name: 'HTTPS-ALT',     severity: 'medium',   protocol: 'tcp', desc: 'TLS alternate' },
    9200: { name: 'ELASTICSEARCH', severity: 'high',     protocol: 'tcp', desc: 'Elasticsearch HTTP' },
    9300: { name: 'ES-CLUSTER',    severity: 'medium',   protocol: 'tcp', desc: 'Elasticsearch cluster' },
    11211:{ name: 'MEMCACHED',     severity: 'high',     protocol: 'tcp', desc: 'Memcached' },
    27017:{ name: 'MONGODB',       severity: 'high',     protocol: 'tcp', desc: 'MongoDB' },
  };

  const PROFILES = {
    quick:    [21,22,23,25,53,80,110,139,143,443,445,3389,3306,5432,8080,8443],
    full:     Object.keys(PORT_SERVICES).map(Number),
    web:      [80, 443, 8000, 8080, 8443, 8888, 9090],
    db:       [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
  };

  // ==========================================================
  // 2. SCAN ENGINE — realistic simulation
  // ==========================================================
  // In production: real socket probes against the target. Here we
  // deterministically synthesise results based on the target so the
  // dashboard always feels real and reproducible.

  // Hosts reachable from a typical LAN scan
  const SIM_NET = [
    { ip: '192.168.1.1',  hostname: 'gateway.local',    os: 'Linux 5.x',     icon: '🖧' },
    { ip: '192.168.1.10', hostname: 'web-prod-01',      os: 'Ubuntu 22.04',  icon: '🖥️' },
    { ip: '192.168.1.11', hostname: 'web-prod-02',      os: 'Ubuntu 22.04',  icon: '🖥️' },
    { ip: '192.168.1.20', hostname: 'db-master',        os: 'Debian 11',     icon: '🗄️' },
    { ip: '192.168.1.21', hostname: 'db-replica',       os: 'Debian 11',     icon: '🗄️' },
    { ip: '192.168.1.30', hostname: 'mail-srv',         os: 'CentOS 7',      icon: '📧' },
    { ip: '192.168.1.40', hostname: 'dev-jenkins',      os: 'Ubuntu 20.04',  icon: '⚙️' },
    { ip: '192.168.1.41', hostname: 'win-fileserver',   os: 'Windows Server 2019', icon: '🗂️' },
    { ip: '192.168.1.50', hostname: 'redis-cache',      os: 'Ubuntu 22.04',  icon: '⚡' },
    { ip: '192.168.1.51', hostname: 'elastic-search',   os: 'Ubuntu 22.04',  icon: '🔍' },
  ];

  // Per-host open ports (deterministic by IP, but noisy)
  const HOST_PORTS = {
    '192.168.1.1':  [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 53,  banner: 'BIND 9.16.1' },
      { port: 80,  banner: 'Apache/2.4.41 (Ubuntu)' },
    ],
    '192.168.1.10': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_7.4' },
      { port: 80,  banner: 'Apache/2.4.49 (Ubuntu)' },
      { port: 443, banner: 'Apache/2.4.49 (Ubuntu)' },
    ],
    '192.168.1.11': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_9.1p1' },
      { port: 80,  banner: 'nginx/1.18.0' },
      { port: 443, banner: 'nginx/1.18.0' },
    ],
    '192.168.1.20': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 3306,banner: '5.7.33-log' },
      { port: 5432,banner: 'PostgreSQL 14.2' },
    ],
    '192.168.1.21': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 5432,banner: 'PostgreSQL 13.3' },
    ],
    '192.168.1.30': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_7.4' },
      { port: 25,  banner: '220 mail-srv ESMTP Postfix' },
      { port: 143, banner: '* OK Dovecot ready.' },
    ],
    '192.168.1.40': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 8080,banner: 'Apache-Coyote/1.1 WordPress/5.8' },
    ],
    '192.168.1.41': [
      { port: 139, banner: '' },
      { port: 445, banner: 'Windows Server 2019 - Samba 4.13.13' },
      { port: 3389,banner: '' },
    ],
    '192.168.1.50': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 6379,banner: 'redis_version:6.0.9' },
    ],
    '192.168.1.51': [
      { port: 22,  banner: 'SSH-2.0-OpenSSH_8.5p1' },
      { port: 9200,banner: '{"number":"7.16.3"}' },
      { port: 9300,banner: '' },
    ],
  };

  // Targets that resolve to a single host (for single-host mode)
  function pickHosts(target, profile) {
    if (!target) return [];
    const ports = PROFILES[profile] || PROFILES.full;

    // Resolve "single host" — match against SIM_NET or treat as custom
    const matches = SIM_NET.filter(h => h.ip === target || h.hostname === target);
    if (matches.length) return matches.map(h => ({
      ...h,
      ports: (HOST_PORTS[h.ip] || []).filter(p => ports.includes(p.port)),
    })).filter(h => h.ports.length > 0);

    // CIDR / list mode — return all hosts with ports intersecting profile
    return SIM_NET.map(h => ({
      ...h,
      ports: (HOST_PORTS[h.ip] || []).filter(p => ports.includes(p.port)),
    })).filter(h => h.ports.length > 0);
  }

  // ==========================================================
  // 3. STATE
  // ==========================================================
  let currentScan = null; // { id, startedAt, finishedAt, target, hosts: [...] }

  // ==========================================================
  // 4. DOM HOOKS
  // ==========================================================
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  $$('.tab').forEach(t => t.addEventListener('click', () => {
    $$('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    const input = $('#targetInput');
    const hint = $('#targetHint');
    if (t.dataset.target === 'host')  { input.value = '192.168.1.10'; hint.textContent = 'Enter an IP or hostname (e.g. 10.0.0.1, scanme.nmap.org)'; }
    if (t.dataset.target === 'cidr')  { input.value = '192.168.1.0/24'; hint.textContent = 'Subnet in CIDR notation. The demo includes 10 representative hosts on 192.168.1.0/24.'; }
    if (t.dataset.target === 'list')  { input.value = '192.168.1.10,192.168.1.20,192.168.1.50'; hint.textContent = 'Comma-separated list of IPs or hostnames.'; }
  }));

  $('#scanBtn').addEventListener('click', startScan);
  $('#rescanBtn')?.addEventListener('click', startScan);
  $('#exportBtn')?.addEventListener('click', exportJson);
  $('#hostFilter')?.addEventListener('input', renderHosts);
  $('#sevFilter')?.addEventListener('change', renderHosts);
  $('#cveSevFilter')?.addEventListener('change', renderCves);
  $('#cveKevFilter')?.addEventListener('change', renderCves);
  $('#chatForm')?.addEventListener('submit', handleChat);
  $$('.suggestions li').forEach(li => li.addEventListener('click', () => {
    $('#chatText').value = li.textContent;
    handleChat(new Event('submit'));
  }));

  // ==========================================================
  // 5. SCAN ORCHESTRATION
  // ==========================================================
  async function startScan() {
    const target = $('#targetInput').value.trim();
    if (!target) return;
    const profile = $('#profileSelect').value;
    const scanId = 'scan_' + Date.now().toString(36);

    const btn = $('#scanBtn');
    btn.disabled = true;
    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg> Scanning…';

    $('#systemStatus').innerHTML = '<span class="dot dot-yellow"></span> Scanning…';
    $('#scanProgress').hidden = false;
    $('#progressFill').style.width = '0%';
    $('#progressPct').textContent = '0%';
    $('#progressText').textContent = 'Resolving targets…';
    $('#progressLog').innerHTML = '';

    log('init', `Scan ${scanId} started against ${target} (profile: ${profile})`);
    log('init', 'Loading NVD CVE database (24,500 entries cached locally)…');
    await sleep(250);

    const hosts = pickHosts(target, profile);
    if (!hosts.length) {
      log('warn', 'No hosts responded. Try a wider CIDR or different target.');
      $('#progressFill').style.width = '100%';
      $('#progressPct').textContent = '100%';
      btn.disabled = false;
      btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg> Start scan';
      $('#systemStatus').innerHTML = '<span class="dot dot-red"></span> No hosts found';
      return;
    }

    log('ok', `Resolved ${hosts.length} live host${hosts.length>1?'s':''}.`);
    await sleep(300);

    // Iterate hosts, ports
    let totalPorts = hosts.reduce((s,h) => s + h.ports.length, 0);
    let done = 0;
    for (const host of hosts) {
      log('init', `Probing ${host.ip} (${host.hostname})…`);
      await sleep(120);
      for (const p of host.ports) {
        const svc = PORT_SERVICES[p.port];
        const detected = detectService(svc.name, p.banner);
        p.service = svc.name;
        p.protocol = svc.protocol;
        p.desc = svc.desc;
        p.severity = svc.severity;
        p.detected = detected;
        p.cves = matchCves(detected, $('#cveCheck').checked);
        if (detected) {
          log('ok', `${host.ip}:${p.port} open  ${svc.name}  ${detected.vendor}/${detected.product}@${detected.version}`);
        } else {
          log('ok', `${host.ip}:${p.port} open  ${svc.name}`);
        }
        if (p.cves.length) {
          for (const c of p.cves) log('warn', `  ↳ ${c.id} (${c.severity} ${c.cvss}) — ${c.desc.slice(0,60)}…`);
        }
        done++;
        const pct = Math.round((done / totalPorts) * 100);
        $('#progressFill').style.width = pct + '%';
        $('#progressPct').textContent = pct + '%';
        $('#progressText').textContent = `Scanning ${done}/${totalPorts} ports…`;
        await sleep(60);
      }
    }

    log('init', 'Finalising scan report…');
    await sleep(300);

    currentScan = {
      id: scanId,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      target, profile,
      hosts
    };

    renderAll();
    $('#systemStatus').innerHTML = '<span class="dot dot-green"></span> Scan complete';
    btn.disabled = false;
    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg> Start scan';
    $('#scanProgress').hidden = true;
  }

  function log(kind, msg) {
    const log = $('#progressLog');
    const line = document.createElement('div');
    line.className = kind === 'ok' ? 'ok' : kind === 'warn' ? 'warn' : '';
    line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  // ==========================================================
  // 6. CVE MATCHING
  // ==========================================================
  function matchCves(detected, enabled) {
    if (!enabled || !detected) return [];
    const out = [];
    for (const entry of CVE_DB) {
      if (entry.vendor !== detected.vendor) continue;
      if (entry.product !== detected.product) continue;
      if (!detected.version.startsWith(entry.versionPrefix)) continue;
      for (const c of entry.cves) out.push(c);
    }
    return out;
  }

  function detectService(svcName, banner) {
    if (!banner) return null;
    const rules = SERVICE_FINGERPRINTS[svcName] || [];
    for (const r of rules) {
      const m = banner.match(r.match);
      if (m) {
        const version = r.versionIdx != null && m[r.versionIdx] ? m[r.versionIdx] : 'unknown';
        return { vendor: r.vendor, product: r.product, version };
      }
    }
    return null;
  }

  // ==========================================================
  // 7. RENDER
  // ==========================================================
  function renderAll() {
    if (!currentScan) return;
    const allCves = currentScan.hosts.flatMap(h => h.ports.flatMap(p => p.cves.map(c => ({ ...c, host: h.ip, hostName: h.hostname, port: p.port, service: p.service }))));
    const totals = {
      hosts: currentScan.hosts.length,
      ports: currentScan.hosts.reduce((s,h) => s + h.ports.length, 0),
      cves: allCves.length,
      critical: allCves.filter(c => c.severity === 'CRITICAL').length,
      high: allCves.filter(c => c.severity === 'HIGH').length,
      medium: allCves.filter(c => c.severity === 'MEDIUM').length,
      low: allCves.filter(c => c.severity === 'LOW').length,
      kev: allCves.filter(c => c.kev).length,
    };

    // hero stats
    $('#statHosts').textContent = totals.hosts;
    $('#statPorts').textContent = totals.ports;
    $('#statCves').textContent = totals.cves;
    $('#statCritical').textContent = totals.critical;

    // dashboard
    $('#emptyState').hidden = true;
    $('#hostsEmpty').hidden = true;
    $('#cvesEmpty').hidden = true;
    $('#chatEmpty').hidden = true;
    $('#dashGrid').hidden = false;
    $('#chatShell').hidden = false;
    $('#kpiCritical').textContent = totals.critical;
    $('#kpiHigh').textContent = totals.high;
    $('#kpiMedium').textContent = totals.medium;
    $('#kpiLow').textContent = totals.low;

    renderSeverityChart(totals);
    renderServiceBars(currentScan);
    renderPortBars(currentScan);
    renderExploitBars(allCves);

    renderHosts();
    renderCves();

    // chat meta
    $('#scanId').textContent = currentScan.id;
    const approxTokens = JSON.stringify(currentScan).length / 4;
    $('#ctxSize').textContent = approxTokens.toFixed(0) + ' tokens';
  }

  function renderSeverityChart(t) {
    const data = [
      { label: 'Critical', value: t.critical, cls: 'crit' },
      { label: 'High',     value: t.high,     cls: 'high' },
      { label: 'Medium',   value: t.medium,   cls: 'med' },
      { label: 'Low',      value: t.low,      cls: 'low' },
    ];
    const max = Math.max(1, ...data.map(d => d.value));
    $('#severityChart').innerHTML = data.map(d => `
      <div class="bar">
        <span class="bar-val">${d.value}</span>
        <div class="bar-fill ${d.cls}" style="height:${Math.max(6, (d.value/max)*140)}px"></div>
        <span class="bar-label">${d.label}</span>
      </div>
    `).join('');
  }

  function renderServiceBars(scan) {
    const svcCve = {};
    for (const h of scan.hosts) for (const p of h.ports) {
      if (p.cves.length) svcCve[p.service] = (svcCve[p.service] || 0) + p.cves.length;
    }
    const entries = Object.entries(svcCve).sort((a,b) => b[1]-a[1]).slice(0,6);
    const max = Math.max(1, ...entries.map(e => e[1]));
    $('#serviceBars').innerHTML = entries.length ? entries.map(([k,v]) => `
      <div class="row">
        <span class="name">${k}</span>
        <div class="track"><div class="fill" style="width:${(v/max)*100}%"></div></div>
        <span class="count">${v}</span>
      </div>
    `).join('') : '<p class="muted small">No service CVEs flagged 🎉</p>';
  }

  function renderPortBars(scan) {
    const portCounts = {};
    for (const h of scan.hosts) for (const p of h.ports) {
      portCounts[p.port] = (portCounts[p.port] || 0) + 1;
    }
    const entries = Object.entries(portCounts).sort((a,b) => b[1]-a[1]).slice(0,6);
    const max = Math.max(1, ...entries.map(e => e[1]));
    $('#portBars').innerHTML = entries.map(([port,count]) => `
      <div class="row">
        <span class="name">:${port} ${PORT_SERVICES[port]?.name || ''}</span>
        <div class="track"><div class="fill" style="width:${(count/max)*100}%"></div></div>
        <span class="count">${count}</span>
      </div>
    `).join('');
  }

  function renderExploitBars(allCves) {
    const kev = allCves.filter(c => c.kev).length;
    const nonKev = allCves.length - kev;
    const max = Math.max(1, kev, nonKev);
    $('#exploitBars').innerHTML = `
      <div class="row">
        <span class="name">Known exploited (KEV)</span>
        <div class="track"><div class="fill crit" style="width:${(kev/max)*100}%"></div></div>
        <span class="count">${kev}</span>
      </div>
      <div class="row">
        <span class="name">No public exploit</span>
        <div class="track"><div class="fill" style="width:${(nonKev/max)*100}%"></div></div>
        <span class="count">${nonKev}</span>
      </div>
    `;
  }

  function renderHosts() {
    if (!currentScan) return;
    const text = ($('#hostFilter')?.value || '').toLowerCase();
    const sevF = $('#sevFilter')?.value || '';
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    const filtered = currentScan.hosts.filter(h => {
      if (text && !h.ip.toLowerCase().includes(text) && !h.hostname.toLowerCase().includes(text)) return false;
      if (sevF) {
        const maxSev = h.ports.reduce((mx,p) => {
          const sev = (p.cves[0]?.severity || p.severity || 'info').toLowerCase();
          return Math.max(mx, sevRank[sev] || 0);
        }, 0);
        if (sevF === 'critical' && maxSev < 4) return false;
        if (sevF === 'high' && maxSev < 3) return false;
        if (sevF === 'medium' && maxSev < 2) return false;
      }
      return true;
    });

    if (!filtered.length) {
      $('#hostsList').innerHTML = '';
      return;
    }

    $('#hostsList').innerHTML = filtered.map(h => {
      const allCves = h.ports.flatMap(p => p.cves);
      const crit = allCves.filter(c => c.severity === 'CRITICAL').length;
      const high = allCves.filter(c => c.severity === 'HIGH').length;
      const med  = allCves.filter(c => c.severity === 'MEDIUM').length;
      const kev  = allCves.filter(c => c.kev).length;

      return `
      <div class="host-card">
        <div class="host-head">
          <div class="host-icon">${h.icon}</div>
          <div class="host-info">
            <h4>${h.hostname} <span class="ip">${h.ip}</span></h4>
            <div class="meta">
              <span>🖥️ ${h.os}</span>
              <span>📡 ${h.ports.length} open</span>
              <span>🔓 ${allCves.length} CVE${allCves.length===1?'':'s'}</span>
              ${kev ? '<span class="pill kev">⚠ KEV</span>' : ''}
            </div>
          </div>
          <div class="host-summary">
            ${crit ? `<span class="pill crit">${crit} crit</span>` : ''}
            ${high ? `<span class="pill high">${high} high</span>` : ''}
            ${med  ? `<span class="pill med">${med} med</span>`  : ''}
          </div>
        </div>
        <div class="host-body">
          <table class="ports-table">
            <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th></tr></thead>
            <tbody>
              ${h.ports.map(p => `
                <tr>
                  <td class="mono">${p.port}/${p.protocol}</td>
                  <td>${p.service} <span class="muted small">— ${p.desc}</span></td>
                  <td class="mono">${p.detected ? `${p.detected.vendor}/${p.detected.product} <strong style="color:var(--accent)">${p.detected.version}</strong>` : '<span class="muted">unknown</span>'}</td>
                  <td><div class="cve-list-cell">
                    ${p.cves.length ? p.cves.map(c => `<span class="cve-chip ${c.severity==='CRITICAL'?'':(c.severity==='HIGH'?'high':'med')}">${c.id} ${c.cvss}</span>`).join('') : '<span class="muted small">none</span>'}
                  </div></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
    }).join('');
  }

  function renderCves() {
    if (!currentScan) return;
    const sevF = $('#cveSevFilter')?.value || '';
    const kevF = $('#cveKevFilter')?.value || '';
    const all = currentScan.hosts.flatMap(h => h.ports.flatMap(p =>
      p.cves.map(c => ({ ...c, host: h.ip, hostName: h.hostname, port: p.port, service: p.service }))
    ));
    const filtered = all.filter(c => {
      if (sevF && c.severity !== sevF) return false;
      if (kevF === 'kev' && !c.kev) return false;
      return true;
    }).sort((a,b) => b.cvss - a.cvss);

    if (!filtered.length) {
      $('#cveList').innerHTML = '';
      return;
    }

    $('#cveList').innerHTML = filtered.map(c => `
      <div class="cve-row sev-${c.severity}">
        <div class="sev-badge">
          <span class="score">${c.cvss.toFixed(1)}</span>
          <span class="lbl">${c.severity}</span>
        </div>
        <div class="cve-body">
          <h4><span class="id">${c.id}</span> ${c.hostName} <span class="muted small">(${c.host}:${c.port} ${c.service})</span></h4>
          <p class="desc">${c.desc}</p>
          <div class="tags">
            <span class="tag">CVSS ${c.cvss}</span>
            ${c.kev ? '<span class="tag kev">KEV — known exploited</span>' : ''}
            <span class="tag cpe">${c.cpe}</span>
          </div>
        </div>
        <div class="cve-actions">
          <button class="btn btn-ghost" onclick="document.getElementById('chatText').value='Tell me about ${c.id}'; document.getElementById('chatForm').dispatchEvent(new Event('submit'))">Ask AI →</button>
        </div>
      </div>
    `).join('');
  }

  function exportJson() {
    if (!currentScan) return;
    const blob = new Blob([JSON.stringify(currentScan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentScan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ==========================================================
  // 8. CHAT WITH YOUR SCAN — RAG-style assistant
  // ==========================================================
  // Uses pattern-matching + templated responses over the scan
  // JSON. In production, replace `generateAnswer` with a call
  // to LangChain RetrievalQA over the scan document.

  async function handleChat(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!currentScan) return;
    const input = $('#chatText');
    const text = input.value.trim();
    if (!text) return;
    input.value = '';

    appendMsg('user', text);
    const typing = appendMsg('typing', '');
    await sleep(350 + Math.random() * 500);
    typing.remove();

    const answer = generateAnswer(text);
    appendMsg('system', answer);
  }

  function appendMsg(kind, html) {
    const t = $('#chatTranscript');
    const div = document.createElement('div');
    if (kind === 'typing') {
      div.className = 'msg msg-system typing';
      div.innerHTML = `
        <span class="msg-avatar">V</span>
        <div class="msg-body"><span></span><span></span><span></span></div>`;
    } else if (kind === 'user') {
      div.className = 'msg msg-user';
      div.innerHTML = `
        <span class="msg-avatar">U</span>
        <div class="msg-body">${escapeHtml(html)}</div>`;
    } else {
      div.className = 'msg msg-system';
      div.innerHTML = `
        <span class="msg-avatar">V</span>
        <div class="msg-body">${html}</div>`;
    }
    t.appendChild(div);
    t.scrollTop = t.scrollHeight;
    return div;
  }
  function escapeHtml(s) { return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  // ==========================================================
  // 9. ANSWER GENERATOR — rule-based "RAG" over scan JSON
  // ==========================================================
  function generateAnswer(q) {
    const ql = q.toLowerCase();
    const scan = currentScan;
    const allCves = scan.hosts.flatMap(h => h.ports.flatMap(p => p.cves.map(c => ({ ...c, host: h.ip, hostName: h.hostname, port: p.port, service: p.service }))));

    // Specific CVE lookup (e.g. "tell me about CVE-2021-41773")
    const cveIdMatch = q.match(/CVE-\d{4}-\d+/i);
    if (cveIdMatch) {
      const id = cveIdMatch[0].toUpperCase();
      const c = allCves.find(x => x.id === id);
      if (c) return `<p><strong>${c.id}</strong> — ${c.desc}</p>
        <p class="muted small">Severity: ${c.severity} · CVSS ${c.cvss} · ${c.kev ? '<span style="color:var(--red)">listed in CISA KEV</span>' : 'no known exploit in CISA KEV'}</p>
        <p>Found on <strong>${c.hostName}</strong> (${c.host}:${c.port}, ${c.service}).</p>
        <p>Recommended action: patch to the latest vendor release and verify with a re-scan.</p>`;
    }

    // Critical / high impact
    if (/(critical|worst|severe)/i.test(ql)) {
      const crit = allCves.filter(c => c.severity === 'CRITICAL');
      if (!crit.length) return `<p>Good news — no CVSS ≥ 9.0 critical CVEs were detected in this scan. ${allCves.filter(c=>c.severity==='HIGH').length ? 'However, ' + allCves.filter(c=>c.severity==='HIGH').length + ' high-severity issues need attention.' : ''}</p>`;
      return `<p>Found <strong>${crit.length} critical</strong> CVE${crit.length>1?'s':''} (CVSS ≥ 9.0):</p>
        <ul>${crit.slice(0,5).map(c => `<li><code>${c.id}</code> on <strong>${c.hostName}</strong> (${c.service}) — ${c.desc.slice(0,90)}${c.kev?' ⚠ KEV':''}</li>`).join('')}</ul>
        <p>These should be remediated <strong>first</strong> — they are likely weaponised and reachable from the network.</p>`;
    }

    // Internet-facing / externally exploitable
    if (/(internet|external|public[- ]facing|outside)/i.test(ql)) {
      const risky = allCves.filter(c => {
        const port = c.port;
        // Heuristic: ports typically reachable from the internet
        return [21,22,23,25,53,80,110,139,143,443,445,587,993,995,3389,8080,8443,9200,11211,27017].includes(port);
      });
      const exploits = risky.filter(c => c.kev);
      return `<p>Of ${allCves.length} total CVEs, <strong>${risky.length}</strong> affect services normally exposed to the internet${exploits.length?`, and <strong style="color:var(--red)">${exploits.length} of those are in the CISA KEV catalog (public exploit available)</span>`:''}.</p>
        ${exploits.length ? `<ul>${exploits.slice(0,5).map(c=>`<li><code>${c.id}</code> on ${c.hostName} (${c.service} on :${c.port})</li>`).join('')}</ul>` : ''}
        <p class="muted small">Heuristic: services on ports typically reachable from outside your network.</p>`;
    }

    // Database
    if (/(database|mysql|postgres|sql|mongo|redis|elastic|memcache)/i.test(ql)) {
      const dbPorts = [1433,1521,3306,5432,6379,9200,11211,27017];
      const dbHits = allCves.filter(c => dbPorts.includes(c.port));
      if (!dbHits.length) return `<p>No database-related CVEs found in this scan. ${scan.hosts.flatMap(h=>h.ports.filter(p=>dbPorts.includes(p.port))).length ? 'Database services were detected but no version-specific CVEs matched the local DB.' : 'No database services (MySQL, PostgreSQL, Mongo, Redis, Elasticsearch, Memcached) were found on the targeted hosts.'}</p>`;
      return `<p>Found <strong>${dbHits.length}</strong> database-related CVE${dbHits.length>1?'s':''}:</p>
        <ul>${dbHits.map(c=>`<li><code>${c.id}</code> ${c.severity} (CVSS ${c.cvss}) — ${c.service} on ${c.hostName}${c.kev?' ⚠ KEV':''}</li>`).join('')}</ul>
        <p class="muted small">Database services should not be exposed to the internet — verify firewall rules.</p>`;
    }

    // Outdated web servers
    if (/(web ?server|outdated|apache|nginx|iis|http)/i.test(ql)) {
      const web = scan.hosts.flatMap(h => h.ports.filter(p => ['HTTP','HTTPS','TOMCAT'].includes(p.service)));
      if (!web.length) return `<p>No web servers detected.</p>`;
      const webCves = web.flatMap(p => p.cves);
      return `<p>Web server inventory:</p>
        <ul>${web.map(p => `<li>${p.detected ? `<code>${p.detected.vendor}/${p.detected.product} ${p.detected.version}</code>` : 'unknown'} on <strong>${p.host || scan.hosts.find(h=>h.ports.includes(p)).hostname}</strong>${p.cves.length?` — <strong>${p.cves.length} CVE${p.cves.length>1?'s':''}</strong>`:''}</li>`).join('')}</ul>
        ${webCves.length?`<p>Web CVEs to patch: ${[...new Set(webCves.map(c=>c.id))].map(id=>`<code>${id}</code>`).join(', ')}</p>`:'<p class="muted small">No CVEs matched against the local database for these web servers.</p>'}`;
    }

    // SSH-specific
    if (/(ssh|openssh)/i.test(ql)) {
      const ssh = scan.hosts.flatMap(h => h.ports.filter(p => p.service === 'SSH'));
      const sshCves = ssh.flatMap(p => p.cves);
      return `<p><strong>${ssh.length}</strong> SSH service${ssh.length===1?'':'s'} running across the scanned hosts${sshCves.length?`, with <strong>${sshCves.length}</strong> known CVEs`:'.'}</p>
        ${ssh.length ? `<ul>${ssh.map(p => `<li>${scan.hosts.find(h=>h.ports.includes(p)).hostname} — OpenSSH <code>${p.detected?.version || 'unknown'}</code></li>`).join('')}</ul>` : ''}
        ${sshCves.length ? `<p>SSH CVEs: ${[...new Set(sshCves.map(c=>c.id))].map(id=>`<code>${id}</code>`).join(', ')}</p>` : ''}`;
    }

    // Known exploited / KEV
    if (/(exploit|kev|public[- ]exploit|weaponis)/i.test(ql)) {
      const kev = allCves.filter(c => c.kev);
      if (!kev.length) return `<p>No CVEs in this scan have a public exploit listed in the CISA KEV catalog.</p>`;
      return `<p><strong>${kev.length}</strong> CVE${kev.length>1?'s':''} on CISA's Known Exploited Vulnerabilities list:</p>
        <ul>${kev.map(c=>`<li><code>${c.id}</code> on ${c.hostName} (${c.service} :${c.port}) — CVSS ${c.cvss}</li>`).join('')}</ul>
        <p>These are actively exploited in the wild. Patch immediately per CISA's remediation timeline.</p>`;
    }

    // Top risks / summary
    if (/(summar|top|priorit|risk|worst)/i.test(ql)) {
      const sorted = [...allCves].sort((a,b) => b.cvss - a.cvss).slice(0,3);
      if (!sorted.length) return `<p>Clean scan — no CVEs flagged. Recommended next steps: re-scan weekly, enable NVD auto-sync.</p>`;
      return `<p>Top 3 risks in this scan:</p>
        <ol>${sorted.map(c=>`<li><strong>${c.id}</strong> (${c.severity} ${c.cvss}) on ${c.hostName} (${c.service} :${c.port})${c.kev?' ⚠ KEV':''}. ${c.desc.slice(0,100)}…</li>`).join('')}</ol>
        <p><strong>Suggested order:</strong> patch the critical+KEV items first (≤24h per CISA), then high-severity (≤7d), then medium.</p>`;
    }

    // Worst host
    if (/(which host|worst|most vulner|highest)/i.test(ql)) {
      const ranked = scan.hosts.map(h => {
        const cves = h.ports.flatMap(p => p.cves);
        const score = cves.reduce((s,c) => s + (c.severity==='CRITICAL'?10:c.severity==='HIGH'?5:c.severity==='MEDIUM'?2:1), 0);
        return { h, score, cveCount: cves.length };
      }).sort((a,b) => b.score - a.score);
      const top = ranked[0];
      if (!top || !top.score) return `<p>No host scored above zero — every host is clean against the local CVE DB.</p>`;
      return `<p><strong>${top.h.hostname}</strong> (${top.h.ip}) is the worst affected, with <strong>${top.cveCount} CVE${top.cveCount>1?'s':''}</strong> and a risk score of ${top.score}.</p>
        <p>The rest of the ranking:</p>
        <ul>${ranked.slice(1,6).map(r=>`<li>${r.h.hostname} (${r.h.ip}) — ${r.cveCount} CVE${r.cveCount===1?'':'s'}, score ${r.score}</li>`).join('')}</ul>`;
    }

    // Remediation
    if (/(remediat|fix|patch|mitigat|how do i fix|recommend)/i.test(ql)) {
      const kev = allCves.filter(c=>c.kev);
      const crit = allCves.filter(c=>c.severity==='CRITICAL');
      const high = allCves.filter(c=>c.severity==='HIGH');
      return `<p><strong>Suggested remediation order</strong>:</p>
        <ol>
          ${kev.length ? `<li><strong>${kev.length} CISA-KEV</strong> — patch within 24h. ${[...new Set(kev.map(c=>c.id))].slice(0,4).map(id=>`<code>${id}</code>`).join(' ')}</li>` : ''}
          ${crit.length ? `<li><strong>${crit.length} other critical CVEs</strong> — patch within 72h.</li>` : ''}
          ${high.length ? `<li><strong>${high.length} high-severity CVEs</strong> — patch within 7 days.</li>` : ''}
          <li>Close unnecessary database ports (${scan.hosts.flatMap(h=>h.ports.filter(p=>[3306,5432,6379,9200,27017].includes(p.port))).length} found).</li>
          <li>Disable plaintext services (Telnet, unencrypted FTP) if present.</li>
          <li>Re-run this scan to verify fixes.</li>
        </ol>`;
    }

    // Counts
    if (/(how many|count|total|number of)/i.test(ql)) {
      return `<p>Scan summary:</p>
        <ul>
          <li>Hosts: <strong>${scan.hosts.length}</strong></li>
          <li>Open ports: <strong>${scan.hosts.reduce((s,h)=>s+h.ports.length,0)}</strong></li>
          <li>CVEs flagged: <strong>${allCves.length}</strong></li>
          <li>Critical: ${allCves.filter(c=>c.severity==='CRITICAL').length}</li>
          <li>High: ${allCves.filter(c=>c.severity==='HIGH').length}</li>
          <li>Medium: ${allCves.filter(c=>c.severity==='MEDIUM').length}</li>
          <li>KEV (active exploit): ${allCves.filter(c=>c.kev).length}</li>
        </ul>`;
    }

    // List all CVEs
    if (/(list|show|all).*cve/i.test(ql)) {
      if (!allCves.length) return `<p>No CVEs found in this scan.</p>`;
      return `<p>All <strong>${allCves.length}</strong> flagged CVEs (sorted by CVSS):</p>
        <ul>${[...allCves].sort((a,b)=>b.cvss-a.cvss).slice(0,20).map(c=>`<li><code>${c.id}</code> ${c.severity} ${c.cvss} — ${c.hostName} (${c.service})</li>`).join('')}</ul>
        ${allCves.length>20?'<p class="muted small">Showing first 20. Use the CVE feed above for the full list.</p>':''}`;
    }

    // Default — context-rich fallback
    return `<p>I can answer questions about this scan (${scan.hosts.length} hosts, ${allCves.length} CVEs). Try asking:</p>
      <ul>
        <li>"Which CVEs are critical and exploitable from the internet?"</li>
        <li>"Did you find any database vulnerabilities?"</li>
        <li>"What's the worst affected host?"</li>
        <li>"Recommend a remediation priority order"</li>
        <li>"Tell me about CVE-XXXX-XXXXX"</li>
      </ul>
      <p class="muted small">In production this is a LangChain RetrievalQA chain over a vector store of your scan JSON — small scans fit directly in the LLM context window.</p>`;
  }

  // ==========================================================
  // 10. SCROLL REVEAL
  // ==========================================================
  const revealTargets = ['.hero-copy','.scanner-card','.section-head','.card','.empty-state','.docs-grid'];
  document.querySelectorAll(revealTargets.join(',')).forEach(el => el.classList.add('reveal'));
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); io.unobserve(e.target); }});
    }, { threshold: 0.12 });
    document.querySelectorAll('.reveal').forEach(el => io.observe(el));
  } else {
    document.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
  }

})();
