<?php
// ============================================================
// OSINT Infrastructure Mapper v7.0
// IP → Domains → Emails → Threat Group Attribution
// ============================================================

$start_time = microtime(true);
$ip = trim($_GET['ip'] ?? '');
$data = []; $ports = []; $dns = []; $error = '';
$vt = []; $abuse = []; $shodan = []; $emails = [];
$attribution = []; $domains = [];

// ──────────────────────────────────────────
// 1. GEO INFO
// ──────────────────────────────────────────
function getIPInfo($ip) {
    $geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=66846719");
    if (!$geo) return [];
    $d = json_decode($geo, true);
    if (($d['status'] ?? '') !== 'success') return [];
    return [
        'country'  => $d['country']      ?? 'Unknown',
        'countryCode'=> $d['countryCode']?? 'XX',
        'region'   => $d['regionName']   ?? 'Unknown',
        'city'     => $d['city']         ?? 'Unknown',
        'zip'      => $d['zip']          ?? '',
        'isp'      => $d['isp']          ?? 'Unknown',
        'org'      => $d['org']          ?? 'Unknown',
        'as'       => $d['as']           ?? 'Unknown',
        'lat'      => $d['lat']          ?? 0,
        'lon'      => $d['lon']          ?? 0,
        'hosting'  => $d['hosting']      ?? false,
        'proxy'    => $d['proxy']        ?? false,
        'mobile'   => $d['mobile']       ?? false,
    ];
}

// ──────────────────────────────────────────
// 2. PORT SCAN
// ──────────────────────────────────────────
function getPorts($ip) {
    $portMap = [
        21=>'FTP',22=>'SSH',23=>'Telnet',25=>'SMTP',
        53=>'DNS',80=>'HTTP',110=>'POP3',143=>'IMAP',
        443=>'HTTPS',445=>'SMB',3306=>'MySQL',
        3389=>'RDP',5900=>'VNC',6379=>'Redis',8080=>'HTTP-Alt',8443=>'HTTPS-Alt'
    ];
    $open = [];
    foreach ($portMap as $p => $svc) {
        $conn = @fsockopen($ip, $p, $err, $errs, 0.3);
        if ($conn) { $open[$p] = $svc; fclose($conn); }
    }
    return $open;
}

// ──────────────────────────────────────────
// 3. DNS / PTR
// ──────────────────────────────────────────
function getDNS($ip) {
    $result = [];
    $host = @gethostbyaddr($ip);
    if ($host && $host !== $ip) {
        $result['ptr'] = $host;
        $parts = explode('.', $host);
        if (count($parts) >= 2)
            $result['domain'] = implode('.', array_slice($parts, -2));
    }
    // MX records if domain found
    if (!empty($result['domain'])) {
        $mx = @dns_get_record($result['domain'], DNS_MX);
        if ($mx) $result['mx'] = array_column($mx, 'target');
        $a  = @dns_get_record($result['domain'], DNS_A);
        if ($a)  $result['a_records'] = array_column($a, 'ip');
    }
    return $result;
}

// ──────────────────────────────────────────
// 4. MOCK APIs (VirusTotal / AbuseIPDB / Shodan)
//    → Realistic demo data seeded from IP
// ──────────────────────────────────────────
function mockVirusTotal($ip) {
    $seed = crc32($ip);
    srand($seed);
    $malicious = rand(0, 12);
    $suspicious = rand(0, 8);
    $engines = ['Kaspersky','Sophos','CrowdStrike','Fortinet','BitDefender',
                'ESET','Symantec','Avast','McAfee','TrendMicro',
                'Palo Alto','Check Point'];
    shuffle($engines);
    $detections = [];
    for ($i = 0; $i < $malicious; $i++) {
        $cats = ['malware','c2','botnet','phishing','spam'];
        $detections[$engines[$i]] = $cats[array_rand($cats)];
    }
    return [
        'malicious'  => $malicious,
        'suspicious' => $suspicious,
        'harmless'   => rand(55, 80),
        'undetected' => rand(3, 10),
        'detections' => $detections,
        'community_score' => round(($malicious / 20) * -100),
        'last_analysis'   => date('Y-m-d', strtotime('-' . rand(1,30) . ' days')),
        'reputation'      => $malicious > 5 ? 'Malicious' : ($malicious > 0 ? 'Suspicious' : 'Clean'),
    ];
}

function mockAbuseIPDB($ip) {
    $seed = crc32($ip . 'abuse');
    srand($seed);
    $score = rand(0, 100);
    $reports = rand(0, 450);
    $cats = ['SSH Brute Force','Port Scan','Web Attack','DDoS','Spam','Phishing','Malware'];
    shuffle($cats);
    return [
        'abuse_score'   => $score,
        'total_reports' => $reports,
        'distinct_users'=> rand(1, min($reports, 120)),
        'last_reported' => date('Y-m-d', strtotime('-' . rand(0, 14) . ' days')),
        'categories'    => array_slice($cats, 0, rand(1,3)),
        'is_whitelisted'=> false,
        'country_code'  => 'XX',
        'usage_type'    => $score > 50 ? 'Data Center/Web Hosting' : 'ISP',
    ];
}

function mockShodan($ip) {
    $seed = crc32($ip . 'shodan');
    srand($seed);
    $banners = [
        'Apache/2.4.51','nginx/1.18.0','OpenSSH_8.2p1',
        'Microsoft-IIS/10.0','lighttpd/1.4.55','Express',
        'PHP/8.0.3','WordPress/6.0'
    ];
    shuffle($banners);
    $vulns = ['CVE-2021-44228','CVE-2021-41773','CVE-2022-22965',
              'CVE-2020-14882','CVE-2023-23397'];
    shuffle($vulns);
    return [
        'hostnames'    => ["host-{$ip}.example.net"],
        'os'           => ['Ubuntu 20.04', 'CentOS 7', 'Windows Server 2019', 'Debian 11'][rand(0,3)],
        'banners'      => array_slice($banners, 0, rand(2,4)),
        'vulns'        => rand(0,1) ? array_slice($vulns, 0, rand(0,3)) : [],
        'last_scan'    => date('Y-m-d H:i', strtotime('-' . rand(1,72) . ' hours')),
        'tags'         => rand(0,1) ? ['cloud','hosting'] : ['vpn','proxy'],
        'isp'          => 'AS' . rand(1000,99999),
    ];
}

function mockEmails($domain) {
    if (empty($domain)) return [];
    $names = ['admin','security','abuse','contact','info','support','noc','postmaster'];
    $result = [];
    $count = rand(2, 5);
    for ($i = 0; $i < $count; $i++) {
        $result[] = [
            'email'      => $names[$i] . '@' . $domain,
            'confidence' => rand(60, 99),
            'type'       => $i === 0 ? 'generic' : 'personal',
            'sources'    => rand(1, 8),
        ];
    }
    return $result;
}

function mockDomains($ip) {
    $seed = crc32($ip . 'domains');
    srand($seed);
    $tlds = ['.com','.net','.org','.io','.cc','.ru','.cn'];
    $prefixes = ['cdn','static','api','mail','mx','vpn','gate','c2','bot','panel'];
    shuffle($prefixes); shuffle($tlds);
    $domains = [];
    $count = rand(2, 6);
    for ($i = 0; $i < $count; $i++) {
        $domains[] = [
            'domain'     => $prefixes[$i] . rand(10,99) . $tlds[$i % count($tlds)],
            'first_seen' => date('Y-m-d', strtotime('-' . rand(30,365) . ' days')),
            'last_seen'  => date('Y-m-d', strtotime('-' . rand(0,30) . ' days')),
            'registrar'  => ['GoDaddy','Namecheap','REG.RU','Tucows','Cloudflare'][rand(0,4)],
        ];
    }
    return $domains;
}

// ──────────────────────────────────────────
// 5. THREAT ATTRIBUTION
// ──────────────────────────────────────────
function getThreatAttribution($vt, $abuse, $ports, $data) {
    $score = 0;
    if (($data['hosting'] ?? false)) $score += 30;
    if (($data['proxy']   ?? false)) $score += 25;
    $score += count($ports) * 3;
    $score += min(($vt['malicious'] ?? 0) * 4, 40);
    $score += min(intval(($abuse['abuse_score'] ?? 0) / 5), 20);
    $score = min($score, 100);

    // Known threat actor patterns (simplified heuristic)
    $groups = [];
    $portKeys = array_keys($ports);

    if (in_array(3389, $portKeys) && ($abuse['abuse_score'] ?? 0) > 60) {
        $groups[] = ['name'=>'Lazarus Group','confidence'=>72,'origin'=>'North Korea',
                     'tactics'=>'RDP Exploitation, Ransomware, Financial Crime',
                     'mitre'=>'T1021.001, T1486, T1190'];
    }
    if (in_array(22, $portKeys) && ($vt['malicious'] ?? 0) > 5) {
        $groups[] = ['name'=>'APT28 (Fancy Bear)','confidence'=>58,'origin'=>'Russia',
                     'tactics'=>'SSH Brute Force, Spear Phishing, Lateral Movement',
                     'mitre'=>'T1110.003, T1566, T1021.004'];
    }
    if (in_array(6379, $portKeys) || in_array(3306, $portKeys)) {
        $groups[] = ['name'=>'TeamTNT','confidence'=>65,'origin'=>'Unknown',
                     'tactics'=>'Cryptomining, Redis/MySQL Exploitation, Container Escape',
                     'mitre'=>'T1190, T1496, T1610'];
    }
    if (($data['hosting'] ?? false) && ($vt['malicious'] ?? 0) > 3) {
        $groups[] = ['name'=>'Cobalt Strike Operator','confidence'=>48,'origin'=>'Unknown',
                     'tactics'=>'C2 Beaconing, Post-Exploitation, Data Exfiltration',
                     'mitre'=>'T1071.001, T1041, T1055'];
    }
    if (empty($groups)) {
        $groups[] = ['name'=>'Unattributed Threat Actor','confidence'=>25,'origin'=>'Unknown',
                     'tactics'=>'Reconnaissance, Opportunistic Scanning',
                     'mitre'=>'T1595, T1046'];
    }

    $level = $score >= 70 ? 'CRITICAL' : ($score >= 45 ? 'HIGH' : ($score >= 20 ? 'MEDIUM' : 'LOW'));
    $levelColor = $score >= 70 ? '#ef4444' : ($score >= 45 ? '#f97316' : ($score >= 20 ? '#eab308' : '#22c55e'));

    return [
        'score'      => $score,
        'level'      => $level,
        'levelColor' => $levelColor,
        'groups'     => $groups,
    ];
}

// ──────────────────────────────────────────
// 6. PROCESS
// ──────────────────────────────────────────
if (!empty($ip)) {
    if (!filter_var($ip, FILTER_VALIDATE_IP) ||
        !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        $error = "Adresse IP invalide ou privée. Utilisez une IP publique.";
    } else {
        $data      = getIPInfo($ip);
        $ports     = getPorts($ip);
        $dns       = getDNS($ip);
        $vt        = mockVirusTotal($ip);
        $abuse     = mockAbuseIPDB($ip);
        $shodan    = mockShodan($ip);
        $domains   = mockDomains($ip);
        $emails    = mockEmails($dns['domain'] ?? substr(md5($ip),0,8).'.net');
        $attribution = getThreatAttribution($vt, $abuse, $ports, $data);
    }
}

// History
$historyFile = 'history.json';
$history = file_exists($historyFile) ? json_decode(file_get_contents($historyFile), true) ?? [] : [];
if (!empty($ip) && !$error && !empty($data)) {
    $exists = false;
    foreach ($history as &$h) {
        if ($h['ip'] === $ip) { $h['last_seen'] = date('Y-m-d H:i:s'); $exists = true; break; }
    }
    if (!$exists) {
        array_unshift($history, [
            'ip'=>$ip,'country'=>$data['country']??'?',
            'threat_score'=>$attribution['score']??0,
            'threat_level'=>$attribution['level']??'LOW',
            'first_seen'=>date('Y-m-d H:i:s'),'last_seen'=>date('Y-m-d H:i:s')
        ]);
        $history = array_slice($history, 0, 30);
    }
    file_put_contents($historyFile, json_encode($history, JSON_PRETTY_PRINT));
}
if (isset($_GET['delete'])) {
    $history = array_values(array_filter($history, fn($h) => $h['ip'] !== $_GET['delete']));
    file_put_contents($historyFile, json_encode($history, JSON_PRETTY_PRINT));
    header('Location: index.php'); exit;
}

$end_time = microtime(true);
$exec_ms = round(($end_time - $start_time) * 1000, 1);
?>
<!DOCTYPE html>
<html dir="ltr" lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Infrastructure Mapper Pro v7</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
<style>
:root {
  --bg:       #050a14;
  --surface:  #0a1628;
  --card:     #0d1f3c;
  --border:   #1a3a5c;
  --accent:   #00d4ff;
  --accent2:  #7c3aed;
  --green:    #10b981;
  --yellow:   #f59e0b;
  --red:      #ef4444;
  --orange:   #f97316;
  --text:     #e2e8f0;
  --muted:    #64748b;
  --mono:     'JetBrains Mono', monospace;
  --sans:     'Syne', sans-serif;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  min-height: 100vh;
  padding-bottom: 100px;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,212,255,.07) 0%, transparent 60%),
    radial-gradient(ellipse 40% 30% at 80% 80%, rgba(124,58,237,.05) 0%, transparent 50%);
}

/* ── GRID BACKGROUND ── */
body::before {
  content:''; position:fixed; inset:0; z-index:0; pointer-events:none;
  background-image:
    linear-gradient(rgba(0,212,255,.03) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,212,255,.03) 1px, transparent 1px);
  background-size: 40px 40px;
}

.wrap { max-width: 1280px; margin: 0 auto; padding: 24px 20px; position:relative; z-index:1; }

/* ── HEADER ── */
.site-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 16px 28px; margin-bottom: 28px;
  background: rgba(10,22,40,.8); backdrop-filter: blur(16px);
  border: 1px solid var(--border); border-radius: 16px;
  position: sticky; top: 12px; z-index: 100;
}
.logo { display:flex; align-items:center; gap:12px; }
.logo-icon {
  width: 40px; height: 40px; background: var(--accent);
  border-radius: 10px; display:grid; place-items:center;
  font-size: 20px; color: var(--bg);
}
.logo-text { font-family: var(--mono); font-weight:700; font-size:15px; }
.logo-text span { color: var(--accent); }
.nav-links { display:flex; gap:8px; }
.nav-btn {
  display:flex; align-items:center; gap:6px;
  padding: 8px 14px; border-radius: 10px;
  background: transparent; border: 1px solid var(--border);
  color: var(--muted); font-family: var(--mono); font-size:12px;
  cursor:pointer; text-decoration:none; transition: all .2s;
}
.nav-btn:hover, .nav-btn.active { background: var(--accent); border-color:var(--accent); color:var(--bg); }

/* ── PIPELINE STEPS ── */
.pipeline {
  display: flex; gap: 0; margin-bottom: 28px; overflow-x: auto;
}
.pipeline-step {
  flex: 1; min-width: 160px;
  display: flex; align-items: center; gap: 0;
}
.step-box {
  flex:1; background: var(--card); border: 1px solid var(--border);
  padding: 14px 16px; position:relative;
  transition: all .3s;
}
.step-box:first-child { border-radius: 12px 0 0 12px; }
.pipeline-step:last-child .step-box { border-radius: 0 12px 12px 0; }
.step-box.active { border-color: var(--accent); background: rgba(0,212,255,.06); }
.step-box.done   { border-color: var(--green); }
.step-num { font-family:var(--mono); font-size:10px; color:var(--muted); margin-bottom:4px; }
.step-label { font-size:12px; font-weight:700; color:var(--text); }
.step-icon { font-size:18px; margin-bottom:6px; }
.arrow {
  width: 0; height: 0;
  border-top: 20px solid transparent;
  border-bottom: 20px solid transparent;
  border-left: 14px solid var(--border);
  flex-shrink: 0; z-index:2;
}
.arrow.done { border-left-color: var(--green); }
.arrow.active { border-left-color: var(--accent); }

/* ── SEARCH BAR ── */
.search-wrap {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 16px; padding: 24px; margin-bottom: 24px;
}
.search-title {
  font-size: 28px; font-weight: 800; margin-bottom: 6px;
  background: linear-gradient(90deg, var(--accent), var(--accent2));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.search-sub { color: var(--muted); font-family:var(--mono); font-size:13px; margin-bottom:20px; }
.search-row { display:flex; gap:10px; }
.ip-input {
  flex:1; padding: 14px 18px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; color: var(--text);
  font-family: var(--mono); font-size:15px; outline:none;
  transition: border-color .2s;
}
.ip-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,212,255,.12); }
.ip-input::placeholder { color: var(--muted); }
.btn-search {
  padding: 14px 28px; background: var(--accent);
  border: none; border-radius: 12px;
  color: var(--bg); font-family:var(--mono); font-weight:700;
  font-size:14px; cursor:pointer; transition: all .2s;
  display:flex; align-items:center; gap:8px; white-space:nowrap;
}
.btn-search:hover { background: #00b8d9; transform:scale(1.02); }
.quick-ips { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
.quick-ip {
  padding: 5px 12px; border-radius: 20px;
  background: var(--surface); border: 1px solid var(--border);
  color: var(--muted); font-family:var(--mono); font-size:11px;
  cursor:pointer; text-decoration:none; transition: all .2s;
}
.quick-ip:hover { border-color:var(--accent); color:var(--accent); }

/* ── CARDS ── */
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: 16px; padding: 22px; margin-bottom: 20px;
  transition: border-color .3s;
}
.card:hover { border-color: rgba(0,212,255,.3); }
.card-header {
  display:flex; align-items:center; justify-content:space-between;
  margin-bottom: 18px;
}
.card-title {
  display:flex; align-items:center; gap:10px;
  font-weight:700; font-size:16px;
}
.card-icon {
  width:32px; height:32px; border-radius:8px;
  display:grid; place-items:center; font-size:14px;
}
.ci-geo  { background: rgba(0,212,255,.15); color:var(--accent); }
.ci-port { background: rgba(124,58,237,.15); color:var(--accent2); }
.ci-vt   { background: rgba(239,68,68,.15);  color:var(--red); }
.ci-abuse{ background: rgba(245,158,11,.15); color:var(--yellow); }
.ci-shodan{background:rgba(16,185,129,.15);  color:var(--green); }
.ci-dom  { background: rgba(124,58,237,.15); color:var(--accent2); }
.ci-mail { background: rgba(0,212,255,.15);  color:var(--accent); }
.ci-attr { background: rgba(239,68,68,.15);  color:var(--red); }
.ci-graph{ background: rgba(0,212,255,.15);  color:var(--accent); }

.badge-pill {
  padding: 3px 10px; border-radius: 20px; font-family:var(--mono);
  font-size:11px; font-weight:600;
}
.bp-green  { background:rgba(16,185,129,.2); color:var(--green); }
.bp-red    { background:rgba(239,68,68,.2);  color:var(--red); }
.bp-yellow { background:rgba(245,158,11,.2); color:var(--yellow); }
.bp-cyan   { background:rgba(0,212,255,.2);  color:var(--accent); }
.bp-purple { background:rgba(124,58,237,.2); color:var(--accent2); }
.bp-orange { background:rgba(249,115,22,.2); color:var(--orange); }

/* ── INFO ROWS ── */
.info-grid { display:grid; gap:2px; }
.info-row {
  display:flex; justify-content:space-between; align-items:center;
  padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,.04);
}
.info-row:last-child { border-bottom:none; }
.info-label { color:var(--muted); font-family:var(--mono); font-size:13px; }
.info-val   { color:var(--text); font-family:var(--mono); font-size:13px; font-weight:600; text-align:right; }

/* ── GRID LAYOUTS ── */
.grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
.grid-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px; }
@media(max-width:900px){ .grid-2,.grid-3 { grid-template-columns:1fr; } }

/* ── THREAT METER ── */
.threat-score-big {
  font-size:64px; font-weight:800; font-family:var(--mono);
  line-height:1; margin-bottom:8px;
}
.threat-bar-wrap {
  height: 12px; background: var(--surface);
  border-radius: 6px; overflow:hidden; margin: 12px 0;
}
.threat-bar-fill {
  height:100%; border-radius:6px;
  background: linear-gradient(90deg, var(--green), var(--yellow), var(--red));
  transition: width .8s cubic-bezier(.4,0,.2,1);
}
.threat-level-badge {
  display:inline-block; padding:6px 16px; border-radius:8px;
  font-family:var(--mono); font-weight:700; font-size:13px; letter-spacing:.05em;
}

/* ── PORT TAGS ── */
.port-grid { display:flex; flex-wrap:wrap; gap:8px; }
.port-tag {
  display:flex; align-items:center; gap:6px;
  padding: 8px 14px; border-radius: 10px;
  background: var(--surface); border: 1px solid var(--border);
  font-family:var(--mono); font-size:12px; cursor:default;
  transition: all .2s;
}
.port-tag:hover { border-color:var(--accent2); transform:translateY(-2px); }
.port-num { color: var(--accent2); font-weight:700; }
.port-svc { color: var(--muted); }
.port-dot { width:7px; height:7px; border-radius:50%; background:var(--green); }
.port-dot.danger { background:var(--red); }
.port-dot.warn   { background:var(--yellow); }

/* ── VT ENGINES ── */
.engine-list { display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }
.engine-tag {
  padding:4px 10px; border-radius:6px; font-family:var(--mono); font-size:11px;
  background:rgba(239,68,68,.15); border:1px solid rgba(239,68,68,.3); color:var(--red);
}

/* ── DOMAIN TABLE ── */
.dom-table { width:100%; border-collapse:collapse; }
.dom-table th, .dom-table td {
  padding: 10px 12px; text-align:left;
  font-family:var(--mono); font-size:12px;
  border-bottom: 1px solid rgba(255,255,255,.05);
}
.dom-table th { color:var(--muted); font-weight:600; }
.dom-table td { color:var(--text); }
.dom-table tr:hover td { background: rgba(0,212,255,.03); }

/* ── EMAIL CARDS ── */
.email-card {
  display:flex; align-items:center; justify-content:space-between;
  padding: 12px 16px; border-radius:10px;
  background: var(--surface); border:1px solid var(--border); margin-bottom:8px;
  transition: border-color .2s;
}
.email-card:hover { border-color:var(--accent); }
.email-addr { font-family:var(--mono); font-size:13px; }
.confidence-bar { width:80px; height:6px; background:var(--bg); border-radius:3px; overflow:hidden; }
.conf-fill { height:100%; background: var(--green); border-radius:3px; }

/* ── ATTRIBUTION ── */
.group-card {
  padding: 16px; border-radius:12px;
  border:1px solid var(--border); background:var(--surface);
  margin-bottom:12px; transition:all .2s;
}
.group-card:hover { border-color:var(--red); }
.group-name { font-weight:700; font-size:15px; margin-bottom:6px; }
.group-meta { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px; }
.group-tactics { color:var(--muted); font-family:var(--mono); font-size:11px; margin-bottom:6px; }
.group-mitre {
  font-family:var(--mono); font-size:10px;
  color: var(--accent2); background:rgba(124,58,237,.1);
  padding:3px 8px; border-radius:4px; display:inline-block;
}
.conf-meter { display:flex; align-items:center; gap:8px; }
.conf-meter-bar { flex:1; height:6px; background:var(--bg); border-radius:3px; overflow:hidden; }
.conf-meter-fill { height:100%; background:var(--orange); border-radius:3px; }

/* ── CANVAS (Maltego Graph) ── */
#maltego-canvas {
  width:100%; height:500px;
  background: var(--surface); border-radius:12px;
  border:1px solid var(--border);
  display:block;
}

/* ── HISTORY ── */
.history-item {
  display:flex; align-items:center; justify-content:space-between;
  padding: 10px 14px; border-radius:10px; margin-bottom:6px;
  background:var(--surface); border:1px solid var(--border);
  transition:all .2s;
}
.history-item:hover { border-color:var(--accent); }
.hist-ip { font-family:var(--mono); font-weight:700; font-size:13px; }
.hist-info { color:var(--muted); font-family:var(--mono); font-size:11px; }
.hist-actions { display:flex; gap:6px; }
.hist-btn {
  padding:4px 10px; border-radius:6px; font-size:11px; font-family:var(--mono);
  cursor:pointer; border:none; transition:all .2s; text-decoration:none;
  display:inline-flex; align-items:center; gap:4px;
}
.hist-btn-view { background:rgba(0,212,255,.15); color:var(--accent); }
.hist-btn-del  { background:rgba(239,68,68,.15);  color:var(--red); }

/* ── EXPORT TOOLBAR ── */
.toolbar {
  display:flex; gap:8px; flex-wrap:wrap; margin-bottom:24px;
}
.tool-btn {
  display:flex; align-items:center; gap:8px;
  padding: 10px 18px; border-radius:10px; border:1px solid var(--border);
  background:var(--card); color:var(--text);
  font-family:var(--mono); font-size:12px; cursor:pointer; transition:all .2s;
  font-weight:600;
}
.tool-btn:hover { transform:translateY(-2px); border-color:var(--accent); color:var(--accent); }
.tool-btn i { font-size:14px; }

/* ── STAT CARDS (mini) ── */
.stat-mini {
  background:var(--card); border:1px solid var(--border); border-radius:12px;
  padding:16px; text-align:center;
}
.stat-val { font-size:32px; font-weight:800; font-family:var(--mono); }
.stat-label { color:var(--muted); font-size:12px; font-family:var(--mono); margin-top:4px; }

/* ── ALERT / ERROR ── */
.alert {
  padding:14px 18px; border-radius:12px; margin-bottom:20px;
  font-family:var(--mono); font-size:13px;
  display:flex; align-items:center; gap:10px;
}
.alert-error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3); color:var(--red); }
.alert-demo  { background:rgba(245,158,11,.08); border:1px solid rgba(245,158,11,.2); color:var(--yellow); }

/* ── MAPS LINK ── */
.map-btn {
  display:inline-flex; align-items:center; gap:8px;
  padding:10px 20px; border-radius:10px; text-decoration:none;
  font-family:var(--mono); font-size:12px; font-weight:600;
  transition:all .2s;
}
.map-btn-google { background:rgba(0,212,255,.12); border:1px solid var(--accent); color:var(--accent); }
.map-btn-osm    { background:rgba(16,185,129,.12); border:1px solid var(--green); color:var(--green); }
.map-btn-bing   { background:rgba(124,58,237,.12); border:1px solid var(--accent2); color:var(--accent2); }
.map-btn:hover  { transform:translateY(-2px); }

/* ── FOOTER ── */
footer {
  text-align:center; padding:24px;
  color:var(--muted); font-family:var(--mono); font-size:11px;
  border-top: 1px solid var(--border); margin-top:40px;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }

/* ── PRINT ── */
@media print {
  body { background:#fff; color:#000; }
  .site-header,.toolbar,.nav-links,footer { display:none; }
  .card { border:1px solid #ddd; background:#fff; page-break-inside:avoid; }
}
</style>
</head>
<body>
<div class="wrap">

<!-- ═══════════════════ HEADER ═══════════════════ -->
<header class="site-header">
  <div class="logo">
    <div class="logo-icon">🕵️</div>
    <div>
      <div class="logo-text">OSINT<span>Mapper</span> <span style="color:var(--muted)">v7</span></div>
      <div style="font-size:10px;color:var(--muted);font-family:var(--mono)">Infrastructure Investigation Platform</div>
    </div>
  </div>
  <nav class="nav-links">
    <a href="index.php" class="nav-btn active"><i class="fas fa-home"></i> Home</a>
    <a href="dashboard.php" class="nav-btn"><i class="fas fa-chart-line"></i> Dashboard</a>
    <a href="compare.php" class="nav-btn"><i class="fas fa-code-branch"></i> Compare</a>
    <a href="about.php" class="nav-btn"><i class="fas fa-info-circle"></i> About</a>
  </nav>
</header>

<!-- ═══════════════════ PIPELINE ═══════════════════ -->
<div class="pipeline">
  <?php
  $steps = [
    ['icon'=>'🎯','num'=>'01','label'=>'IP Suspecte'],
    ['icon'=>'🔍','num'=>'02','label'=>'Enrichissement'],
    ['icon'=>'🌐','num'=>'03','label'=>'Domaines & Emails'],
    ['icon'=>'⚠️','num'=>'04','label'=>'Réputation'],
    ['icon'=>'🎭','num'=>'05','label'=>'Attribution'],
  ];
  $done = !empty($ip) && !$error && !empty($data);
  foreach ($steps as $i => $s) {
    $cls = $done ? 'done' : ($i===0 && !empty($ip) ? 'active' : '');
    echo '<div class="pipeline-step">';
    if ($i > 0) echo '<div class="arrow'.($done?' done':'').'"></div>';
    echo "<div class=\"step-box $cls\">";
    echo "<div class=\"step-icon\">{$s['icon']}</div>";
    echo "<div class=\"step-num\">{$s['num']}</div>";
    echo "<div class=\"step-label\">{$s['label']}</div>";
    echo '</div></div>';
  }
  ?>
</div>

<!-- ═══════════════════ SEARCH ═══════════════════ -->
<div class="search-wrap">
  <div class="search-title">🔍 Investigation OSINT</div>
  <div class="search-sub">IP → Domains → Emails → Threat Actor Attribution</div>
  <form method="GET" class="search-row">
    <input class="ip-input" type="text" name="ip"
      placeholder="Enter suspicious IP address  (e.g. 185.220.101.45)"
      value="<?=htmlspecialchars($ip)?>">
    <button class="btn-search" type="submit">
      <i class="fas fa-search"></i> Investigate
    </button>
  </form>
  <div class="quick-ips">
    <span style="font-size:11px;color:var(--muted);font-family:var(--mono);margin-right:4px;">Quick test:</span>
    <?php foreach(['8.8.8.8','1.1.1.1','185.220.101.45','45.33.32.156','104.21.0.1'] as $qip): ?>
    <a class="quick-ip" href="?ip=<?=$qip?>"><?=$qip?></a>
    <?php endforeach; ?>
  </div>
</div>

<?php if ($error): ?>
<div class="alert alert-error"><i class="fas fa-exclamation-triangle"></i> <?=htmlspecialchars($error)?></div>
<?php endif; ?>

<?php if (!empty($ip) && !$error && !empty($data)): ?>

<div class="alert alert-demo">
  <i class="fas fa-flask"></i>
  <span>Mode démo actif — Les données VirusTotal, AbuseIPDB, Shodan et Hunter.io sont simulées à partir de l'IP. Les données géographiques sont réelles.</span>
</div>

<!-- ═══════════════════ TOOLBAR ═══════════════════ -->
<div class="toolbar">
  <button class="tool-btn" onclick="copyReport()"><i class="fas fa-copy"></i> Copier le rapport</button>
  <button class="tool-btn" onclick="exportJSON()"><i class="fas fa-download"></i> Export JSON</button>
  <button class="tool-btn" onclick="exportPDF()"><i class="fas fa-file-pdf"></i> Export PDF</button>
  <button class="tool-btn" onclick="window.print()"><i class="fas fa-print"></i> Imprimer</button>
  <span style="margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted);align-self:center;">
    ⏱ <?=$exec_ms?>ms
  </span>
</div>

<!-- ═══════════════════ THREAT SCORE (FULL WIDTH) ═══════════════════ -->
<div class="card" style="border-color:<?=$attribution['levelColor']?>40">
  <div class="card-header">
    <div class="card-title">
      <div class="card-icon ci-attr"><i class="fas fa-shield-alt"></i></div>
      Threat Score Global
    </div>
    <span class="badge-pill <?= $attribution['score']>=70?'bp-red':($attribution['score']>=45?'bp-orange':($attribution['score']>=20?'bp-yellow':'bp-green')) ?>">
      <?=$attribution['level']?>
    </span>
  </div>
  <div class="grid-3" style="gap:24px;align-items:center">
    <div style="text-align:center">
      <div class="threat-score-big" style="color:<?=$attribution['levelColor']?>"><?=$attribution['score']?>%</div>
      <div style="color:var(--muted);font-family:var(--mono);font-size:12px">Threat Score</div>
    </div>
    <div style="grid-column:span 2">
      <div class="threat-bar-wrap">
        <div class="threat-bar-fill" style="width:<?=$attribution['score']?>%"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:4px">
        <span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
      </div>
      <div style="margin-top:16px;display:flex;flex-wrap:wrap;gap:8px">
        <?php
        $factors = [
          ['Hosting Server', $data['hosting'] ? '+30pts' : '—', $data['hosting'] ? 'bp-red' : 'bp-green'],
          ['Proxy/VPN', $data['proxy'] ? '+25pts' : '—', $data['proxy'] ? 'bp-yellow' : 'bp-green'],
          ['Open Ports', '+' . (count($ports)*3) . 'pts', 'bp-purple'],
          ['VT Malicious', '+' . ($vt['malicious']*4) . 'pts', $vt['malicious']>0?'bp-red':'bp-green'],
          ['AbuseIPDB', '+' . (int)($abuse['abuse_score']/5) . 'pts', $abuse['abuse_score']>50?'bp-orange':'bp-green'],
        ];
        foreach($factors as $f):?>
        <div style="display:flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border)">
          <span style="font-family:var(--mono);font-size:11px;color:var(--muted)"><?=$f[0]?></span>
          <span class="badge-pill <?=$f[2]?>" style="font-size:10px"><?=$f[1]?></span>
        </div>
        <?php endforeach;?>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════ GEO + SHODAN ═══════════════════ -->
<div class="grid-2">
  <!-- GEO -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-geo"><i class="fas fa-map-marker-alt"></i></div>
        Informations Géographiques
      </div>
      <img src="https://flagcdn.com/20x15/<?=strtolower($data['countryCode']??'xx')?>.png"
           alt="flag" style="border-radius:2px" onerror="this.style.display='none'">
    </div>
    <div class="info-grid">
      <?php $geoRows = [
        ['🌍 Pays',   $data['country']],
        ['🏙️ Ville',  $data['city'].($data['zip']?' ('.$data['zip'].')':'')],
        ['📡 ISP',    $data['isp']],
        ['🏢 Org',    $data['org']],
        ['🔄 ASN',    $data['as']],
        ['📍 Coords', $data['lat'].', '.$data['lon']],
        ['🛡️ Hosting',$data['hosting']?'✅ Oui':'❌ Non'],
        ['🔒 Proxy',  $data['proxy']?'⚠️ Oui':'✅ Non'],
        ['📱 Mobile', $data['mobile']?'Oui':'Non'],
      ];
      foreach($geoRows as $r):?>
      <div class="info-row">
        <span class="info-label"><?=$r[0]?></span>
        <span class="info-val"><?=htmlspecialchars($r[1])?></span>
      </div>
      <?php endforeach;?>
    </div>
    <?php if($data['lat']!=0): ?>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px">
      <a class="map-btn map-btn-google" href="https://www.google.com/maps?q=<?=$data['lat']?>,<?=$data['lon']?>" target="_blank"><i class="fas fa-map"></i> Google Maps</a>
      <a class="map-btn map-btn-osm" href="https://www.openstreetmap.org/?mlat=<?=$data['lat']?>&mlon=<?=$data['lon']?>&zoom=10" target="_blank"><i class="fas fa-globe"></i> OpenStreetMap</a>
    </div>
    <?php endif;?>
  </div>

  <!-- SHODAN -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-shodan"><i class="fas fa-server"></i></div>
        Shodan Intelligence
      </div>
      <span class="badge-pill bp-green">DEMO</span>
    </div>
    <div class="info-grid">
      <?php $shodanRows = [
        ['💻 OS',       $shodan['os']],
        ['🔖 Hostname', $shodan['hostnames'][0]??'N/A'],
        ['🕒 Last Scan',$shodan['last_scan']],
        ['🏷️ Tags',     implode(', ',$shodan['tags'])],
        ['🌐 ISP/ASN',  $shodan['isp']],
      ];
      foreach($shodanRows as $r):?>
      <div class="info-row">
        <span class="info-label"><?=$r[0]?></span>
        <span class="info-val"><?=htmlspecialchars($r[1])?></span>
      </div>
      <?php endforeach;?>
    </div>
    <div style="margin-top:14px">
      <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:8px">BANNERS DETECTED</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        <?php foreach($shodan['banners'] as $b):?>
        <span class="badge-pill bp-cyan"><?=htmlspecialchars($b)?></span>
        <?php endforeach;?>
      </div>
    </div>
    <?php if(!empty($shodan['vulns'])):?>
    <div style="margin-top:14px;padding:10px 14px;border-radius:8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2)">
      <div style="font-family:var(--mono);font-size:11px;color:var(--red);margin-bottom:6px">⚠️ VULNERABILITIES FOUND</div>
      <?php foreach($shodan['vulns'] as $v):?>
      <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=<?=$v?>" target="_blank"
         style="display:inline-block;margin:2px 4px 2px 0;padding:3px 8px;border-radius:4px;background:rgba(239,68,68,.15);color:var(--red);font-family:var(--mono);font-size:11px;text-decoration:none"><?=$v?></a>
      <?php endforeach;?>
    </div>
    <?php endif;?>
  </div>
</div>

<!-- ═══════════════════ PORTS + VT ═══════════════════ -->
<div class="grid-2">
  <!-- PORTS -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-port"><i class="fas fa-plug"></i></div>
        Ports Ouverts
      </div>
      <span class="badge-pill <?=count($ports)>4?'bp-red':(count($ports)>1?'bp-yellow':'bp-green')?>">
        <?=count($ports)?> détectés
      </span>
    </div>
    <?php if(empty($ports)):?>
    <p style="color:var(--muted);font-family:var(--mono);font-size:13px">✅ Aucun port commun ouvert détecté</p>
    <?php else:?>
    <div class="port-grid">
      <?php
      $dangerous = [21,23,445,3389,5900,6379];
      $warning   = [22,25,110,3306];
      foreach($ports as $p=>$svc):
        $dot = in_array($p,$dangerous)?'danger':(in_array($p,$warning)?'warn':'');
      ?>
      <div class="port-tag">
        <div class="port-dot <?=$dot?>"></div>
        <span class="port-num"><?=$p?></span>
        <span class="port-svc"><?=$svc?></span>
      </div>
      <?php endforeach;?>
    </div>
    <?php endif;?>
  </div>

  <!-- VIRUSTOTAL -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-vt"><i class="fas fa-virus"></i></div>
        VirusTotal Analysis
      </div>
      <span class="badge-pill <?=$vt['malicious']>5?'bp-red':($vt['malicious']>0?'bp-yellow':'bp-green')?>">
        <?=$vt['reputation']?>
      </span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px">
      <?php $vtStats = [
        ['Malicious',$vt['malicious'],'var(--red)'],
        ['Suspicious',$vt['suspicious'],'var(--yellow)'],
        ['Harmless',$vt['harmless'],'var(--green)'],
        ['Undetected',$vt['undetected'],'var(--muted)'],
      ];
      foreach($vtStats as $vs):?>
      <div style="text-align:center;padding:12px;border-radius:10px;background:var(--surface);border:1px solid var(--border)">
        <div style="font-size:22px;font-weight:800;font-family:var(--mono);color:<?=$vs[2]?>"><?=$vs[1]?></div>
        <div style="font-size:10px;color:var(--muted);font-family:var(--mono)"><?=$vs[0]?></div>
      </div>
      <?php endforeach;?>
    </div>
    <?php if(!empty($vt['detections'])):?>
    <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:6px">DETECTION ENGINES</div>
    <div class="engine-list">
      <?php foreach($vt['detections'] as $eng=>$cat):?>
      <span class="engine-tag" title="<?=htmlspecialchars($cat)?>"><?=htmlspecialchars($eng)?></span>
      <?php endforeach;?>
    </div>
    <?php endif;?>
    <div class="info-row" style="margin-top:10px">
      <span class="info-label">Community Score</span>
      <span class="info-val" style="color:<?=$vt['community_score']<0?'var(--red)':'var(--green)'?>"><?=$vt['community_score']?></span>
    </div>
    <div class="info-row">
      <span class="info-label">Last Analysis</span>
      <span class="info-val"><?=$vt['last_analysis']?></span>
    </div>
  </div>
</div>

<!-- ═══════════════════ ABUSEIPDB ═══════════════════ -->
<div class="card">
  <div class="card-header">
    <div class="card-title">
      <div class="card-icon ci-abuse"><i class="fas fa-exclamation-triangle"></i></div>
      AbuseIPDB Report
    </div>
    <span class="badge-pill <?=$abuse['abuse_score']>75?'bp-red':($abuse['abuse_score']>40?'bp-orange':'bp-green')?>">
      Score: <?=$abuse['abuse_score']?>%
    </span>
  </div>
  <div class="grid-3">
    <div style="text-align:center;padding:20px;border-radius:12px;background:var(--surface);border:1px solid var(--border)">
      <div style="font-size:42px;font-weight:800;font-family:var(--mono);color:<?=$abuse['abuse_score']>60?'var(--red)':'var(--yellow)'?>"><?=$abuse['abuse_score']?>%</div>
      <div style="color:var(--muted);font-family:var(--mono);font-size:11px;margin-top:4px">Confidence of Abuse</div>
    </div>
    <div>
      <div class="info-grid">
        <div class="info-row"><span class="info-label">Total Reports</span><span class="info-val"><?=$abuse['total_reports']?></span></div>
        <div class="info-row"><span class="info-label">Distinct Users</span><span class="info-val"><?=$abuse['distinct_users']?></span></div>
        <div class="info-row"><span class="info-label">Last Reported</span><span class="info-val"><?=$abuse['last_reported']?></span></div>
        <div class="info-row"><span class="info-label">Usage Type</span><span class="info-val"><?=$abuse['usage_type']?></span></div>
      </div>
    </div>
    <div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:10px">ATTACK CATEGORIES</div>
      <?php foreach($abuse['categories'] as $cat):?>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding:8px 12px;border-radius:8px;background:var(--surface);border:1px solid rgba(245,158,11,.2)">
        <span style="color:var(--yellow)">⚡</span>
        <span style="font-family:var(--mono);font-size:12px"><?=htmlspecialchars($cat)?></span>
      </div>
      <?php endforeach;?>
    </div>
  </div>
</div>

<!-- ═══════════════════ DOMAINS + EMAILS ═══════════════════ -->
<div class="grid-2">
  <!-- DOMAINS -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-dom"><i class="fas fa-globe"></i></div>
        Domaines Associés
      </div>
      <span class="badge-pill bp-purple"><?=count($domains)?> trouvés</span>
    </div>
    <?php if(!empty($dns['ptr'])):?>
    <div style="margin-bottom:12px;padding:10px 14px;border-radius:8px;background:var(--surface);border:1px solid var(--border)">
      <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">PTR Record: </span>
      <span style="font-family:var(--mono);font-size:12px;color:var(--accent)"><?=htmlspecialchars($dns['ptr'])?></span>
    </div>
    <?php endif;?>
    <table class="dom-table">
      <thead><tr>
        <th>Domaine</th><th>Registrar</th><th>Last Seen</th>
      </tr></thead>
      <tbody>
      <?php foreach($domains as $d):?>
      <tr>
        <td style="color:var(--accent)"><?=htmlspecialchars($d['domain'])?></td>
        <td><?=htmlspecialchars($d['registrar'])?></td>
        <td><?=$d['last_seen']?></td>
      </tr>
      <?php endforeach;?>
      </tbody>
    </table>
  </div>

  <!-- EMAILS -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <div class="card-icon ci-mail"><i class="fas fa-envelope"></i></div>
        Emails Découverts (Hunter.io)
      </div>
      <span class="badge-pill bp-cyan"><?=count($emails)?> emails</span>
    </div>
    <?php foreach($emails as $e):?>
    <div class="email-card">
      <div>
        <div class="email-addr">✉️ <?=htmlspecialchars($e['email'])?></div>
        <div style="color:var(--muted);font-family:var(--mono);font-size:10px;margin-top:2px">
          Type: <?=$e['type']?> · Sources: <?=$e['sources']?>
        </div>
      </div>
      <div style="text-align:right">
        <div style="font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:4px"><?=$e['confidence']?>%</div>
        <div class="confidence-bar">
          <div class="conf-fill" style="width:<?=$e['confidence']?>%"></div>
        </div>
        <button onclick="copyTxt('<?=htmlspecialchars($e['email'])?>')"
          style="margin-top:4px;padding:2px 8px;border-radius:4px;font-size:10px;font-family:var(--mono);background:rgba(0,212,255,.1);color:var(--accent);border:none;cursor:pointer">
          📋 Copy
        </button>
      </div>
    </div>
    <?php endforeach;?>
  </div>
</div>

<!-- ═══════════════════ ATTRIBUTION ═══════════════════ -->
<div class="card" style="border-color:rgba(239,68,68,.3)">
  <div class="card-header">
    <div class="card-title">
      <div class="card-icon ci-attr"><i class="fas fa-user-secret"></i></div>
      Threat Actor Attribution
    </div>
    <span class="badge-pill bp-red">MITRE ATT&amp;CK</span>
  </div>
  <p style="color:var(--muted);font-family:var(--mono);font-size:12px;margin-bottom:16px">
    Analyse heuristique basée sur les indicateurs collectés — corrélation avec les TTPs connus.
  </p>
  <?php foreach($attribution['groups'] as $g):?>
  <div class="group-card">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
      <div style="flex:1">
        <div class="group-name">🎭 <?=htmlspecialchars($g['name'])?></div>
        <div class="group-meta">
          <span class="badge-pill bp-red">🌍 <?=htmlspecialchars($g['origin'])?></span>
          <span class="badge-pill bp-orange">Confidence: <?=$g['confidence']?>%</span>
        </div>
        <div class="group-tactics">Tactics: <?=htmlspecialchars($g['tactics'])?></div>
        <div><span class="group-mitre"><?=htmlspecialchars($g['mitre'])?></span></div>
      </div>
      <div style="min-width:120px">
        <div style="font-family:var(--mono);font-size:10px;color:var(--muted);margin-bottom:4px">CONFIDENCE</div>
        <div class="conf-meter">
          <div class="conf-meter-bar">
            <div class="conf-meter-fill" style="width:<?=$g['confidence']?>%"></div>
          </div>
          <span style="font-family:var(--mono);font-size:11px;color:var(--orange);min-width:32px"><?=$g['confidence']?>%</span>
        </div>
      </div>
    </div>
  </div>
  <?php endforeach;?>
</div>

<!-- ═══════════════════ MALTEGO GRAPH ═══════════════════ -->
<div class="card">
  <div class="card-header">
    <div class="card-title">
      <div class="card-icon ci-graph"><i class="fas fa-project-diagram"></i></div>
      Infrastructure Graph (Maltego Style)
    </div>
    <div style="display:flex;gap:10px;font-family:var(--mono);font-size:11px">
      <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:50%;background:var(--accent);display:inline-block"></span>IP</span>
      <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:50%;background:var(--green);display:inline-block"></span>Domaine</span>
      <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:50%;background:var(--yellow);display:inline-block"></span>Email</span>
      <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:50%;background:var(--red);display:inline-block"></span>Port</span>
      <span style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;border-radius:50%;background:var(--accent2);display:inline-block"></span>Actor</span>
    </div>
  </div>
  <canvas id="maltego-canvas"></canvas>
</div>

<!-- ═══════════════════ HISTORY ═══════════════════ -->
<div class="card">
  <div class="card-header">
    <div class="card-title">
      <div class="card-icon ci-geo"><i class="fas fa-history"></i></div>
      Historique des Investigations
    </div>
    <a href="?delete_all=1" onclick="return confirm('Effacer tout?')"
       style="font-family:var(--mono);font-size:11px;color:var(--red);text-decoration:none">
      🗑 Tout effacer
    </a>
  </div>
  <?php if(empty($history)):?>
  <p style="color:var(--muted);font-family:var(--mono);font-size:13px">Aucune investigation précédente.</p>
  <?php else: foreach(array_slice($history,0,10) as $h):
    $lvl = $h['threat_level']??'LOW';
    $lc  = $lvl==='CRITICAL'?'bp-red':($lvl==='HIGH'?'bp-orange':($lvl==='MEDIUM'?'bp-yellow':'bp-green'));
  ?>
  <div class="history-item">
    <div>
      <div class="hist-ip"><?=htmlspecialchars($h['ip'])?></div>
      <div class="hist-info"><?=htmlspecialchars($h['country'])?> · <?=$h['last_seen']?></div>
    </div>
    <span class="badge-pill <?=$lc?>"><?=$lvl?> — <?=$h['threat_score']??0?>%</span>
    <div class="hist-actions">
      <a class="hist-btn hist-btn-view" href="?ip=<?=urlencode($h['ip'])?>">🔍 Analyser</a>
      <a class="hist-btn hist-btn-del"  href="?delete=<?=urlencode($h['ip'])?>"
         onclick="return confirm('Supprimer <?=htmlspecialchars($h['ip'])?>?')">✖</a>
    </div>
  </div>
  <?php endforeach; endif;?>
</div>

<?php endif; // end if IP ?>

<footer>
  OSINT Infrastructure Mapper v7 · Données géographiques réelles · Shodan/VT/AbuseIPDB en mode démo
</footer>
</div>

<!-- ═══════════════════ SCRIPTS ═══════════════════ -->
<script>
// ── Maltego Graph ──────────────────────────────────────────────────────────
(function(){
  const canvas = document.getElementById('maltego-canvas');
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth, H = 500;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  canvas.style.height = H + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const ip      = <?=json_encode($ip)?>;
  const country = <?=json_encode($data['country']??'')?>;
  const isp     = <?=json_encode(substr($data['isp']??'',0,20))?>;
  const ports   = <?=json_encode(array_keys($ports))?>;
  const domains = <?=json_encode(array_column($domains,'domain'))?>;
  const emails  = <?=json_encode(array_column($emails,'email'))?>;
  const actors  = <?=json_encode(array_column($attribution['groups'],'name'))?>;
  const score   = <?=json_encode($attribution['score'])?>;
  const lvlColor= <?=json_encode($attribution['levelColor'])?>;

  // Background
  ctx.fillStyle = '#0a1628';
  ctx.fillRect(0,0,W,H);

  // Grid
  ctx.strokeStyle = 'rgba(0,212,255,0.04)';
  ctx.lineWidth = 1;
  for(let x=0; x<W; x+=40){ ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }
  for(let y=0; y<H; y+=40){ ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }

  const cx = W/2, cy = H/2;

  function drawEdge(x1,y1,x2,y2,color='#334155') {
    ctx.beginPath();
    ctx.moveTo(x1,y1); ctx.lineTo(x2,y2);
    ctx.strokeStyle = color; ctx.lineWidth = 1.5;
    ctx.setLineDash([4,4]);
    ctx.stroke();
    ctx.setLineDash([]);
    // Arrow
    const ang = Math.atan2(y2-y1, x2-x1);
    const ax = x2-12*Math.cos(ang), ay = y2-12*Math.sin(ang);
    ctx.beginPath();
    ctx.moveTo(ax, ay);
    ctx.lineTo(ax-7*Math.cos(ang-Math.PI/6), ay-7*Math.sin(ang-Math.PI/6));
    ctx.lineTo(ax-7*Math.cos(ang+Math.PI/6), ay-7*Math.sin(ang+Math.PI/6));
    ctx.fillStyle = color; ctx.fill();
  }

  function drawNode(x,y,label,color,r=22,icon='') {
    // Glow
    const grd = ctx.createRadialGradient(x,y,0,x,y,r*2);
    grd.addColorStop(0, color+'40');
    grd.addColorStop(1, 'transparent');
    ctx.beginPath(); ctx.arc(x,y,r*2,0,Math.PI*2);
    ctx.fillStyle = grd; ctx.fill();
    // Circle
    ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
    ctx.fillStyle = color+'22';
    ctx.strokeStyle = color; ctx.lineWidth = 2;
    ctx.fill(); ctx.stroke();
    // Icon / text
    ctx.font = 'bold 12px JetBrains Mono, monospace';
    ctx.fillStyle = color;
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(icon||label.substring(0,4), x, y);
    // Label below
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.fillStyle = '#94a3b8';
    ctx.fillText(label.length>18?label.substring(0,16)+'…':label, x, y+r+12);
  }

  // ── Central IP node ──
  const centralR = 32;
  const grd = ctx.createRadialGradient(cx,cy,0,cx,cy,centralR*3);
  grd.addColorStop(0, '#00d4ff30');
  grd.addColorStop(1, 'transparent');
  ctx.beginPath(); ctx.arc(cx,cy,centralR*3,0,Math.PI*2);
  ctx.fillStyle = grd; ctx.fill();

  ctx.beginPath(); ctx.arc(cx,cy,centralR,0,Math.PI*2);
  ctx.fillStyle = '#00d4ff15';
  ctx.strokeStyle = '#00d4ff'; ctx.lineWidth = 3;
  ctx.fill(); ctx.stroke();
  ctx.font = 'bold 11px JetBrains Mono, monospace';
  ctx.fillStyle = '#00d4ff'; ctx.textAlign='center'; ctx.textBaseline='middle';
  ctx.fillText(ip, cx, cy);
  ctx.font = '9px JetBrains Mono, monospace';
  ctx.fillStyle = '#64748b';
  ctx.fillText(country, cx, cy+centralR+12);

  // ── ISP ──
  const ispX=cx-200, ispY=cy-140;
  drawEdge(cx-centralR*0.7, cy-centralR*0.7, ispX+20, ispY+20, '#1a3a5c');
  drawNode(ispX, ispY, isp||'ISP', '#64748b', 20, '📡');

  // ── Score node ──
  const scX=cx+180, scY=cy-130;
  drawEdge(cx+centralR*0.7, cy-centralR*0.7, scX-20, scY+20, lvlColor);
  drawNode(scX, scY, score+'% Risk', lvlColor, 24, '⚠');

  // ── Domains (left arc) ──
  const maxDom = Math.min(domains.length, 4);
  for(let i=0; i<maxDom; i++){
    const ang = -Math.PI*0.8 + (i/(maxDom-1||1))*Math.PI*0.6;
    const r = 170;
    const dx = cx + r*Math.cos(ang), dy = cy + r*Math.sin(ang);
    drawEdge(cx+centralR*Math.cos(ang), cy+centralR*Math.sin(ang), dx, dy, '#10b981');
    drawNode(dx, dy, domains[i], '#10b981', 18, '🌐');
  }

  // ── Emails (bottom arc) ──
  const maxMail = Math.min(emails.length, 3);
  for(let i=0; i<maxMail; i++){
    const ang = Math.PI*0.25 + (i/(maxMail-1||1))*Math.PI*0.5;
    const r = 160;
    const ex = cx + r*Math.cos(ang), ey = cy + r*Math.sin(ang);
    drawEdge(cx+centralR*Math.cos(ang), cy+centralR*Math.sin(ang), ex, ey, '#f59e0b');
    drawNode(ex, ey, emails[i], '#f59e0b', 18, '✉');
  }

  // ── Ports (right arc) ──
  const maxPort = Math.min(ports.length, 5);
  for(let i=0; i<maxPort; i++){
    const ang = -Math.PI*0.3 + (i/(maxPort-1||1))*Math.PI*0.6;
    const r = 165;
    const px = cx + r*Math.cos(ang), py = cy + r*Math.sin(ang);
    const dangerous = [21,23,445,3389,5900,6379].includes(ports[i]);
    const c = dangerous?'#ef4444':'#7c3aed';
    drawEdge(cx+centralR*Math.cos(ang), cy+centralR*Math.sin(ang), px, py, c);
    drawNode(px, py, ':'+ports[i], c, 16, '🔌');
  }

  // ── Threat Actor ──
  if(actors.length){
    const aX=cx, aY=cy+180;
    drawEdge(cx, cy+centralR, aX, aY-22, '#ef4444');
    drawNode(aX, aY, actors[0], '#ef4444', 22, '🎭');
  }
})();

// ── Utilities ──────────────────────────────────────────────────────────────
function copyTxt(t) {
  navigator.clipboard.writeText(t);
  const el = event.target;
  el.textContent = '✅ Done'; setTimeout(()=>el.textContent='📋 Copy', 1500);
}

function copyReport() {
  const txt = `
OSINT Investigation Report
IP: <?=addslashes($ip)?>
Country: <?=addslashes($data['country']??'')?>
ISP: <?=addslashes($data['isp']??'')?>
City: <?=addslashes($data['city']??'')?>
ASN: <?=addslashes($data['as']??'')?>
Hosting: <?=$data['hosting']?'Yes':'No'?>
Proxy/VPN: <?=$data['proxy']?'Yes':'No'?>

Open Ports: <?=implode(', ', array_map(fn($p,$s)=>$p.'/'.$s, array_keys($ports), $ports))?> 

VirusTotal: <?=$vt['malicious']?> malicious / <?=$vt['suspicious']?> suspicious
AbuseIPDB Score: <?=$abuse['abuse_score']?>%  (<?=$abuse['total_reports']?> reports)

Threat Score: <?=$attribution['score']?>% — <?=$attribution['level']?>

Associated Domains: <?=implode(', ', array_column($domains,'domain'))?>

Emails: <?=implode(', ', array_column($emails,'email'))?>

Attribution: <?=implode(', ', array_column($attribution['groups'],'name'))?>

Generated: <?=date('Y-m-d H:i:s')?>
`.trim();
  navigator.clipboard.writeText(txt);
  alert('✅ Rapport copié dans le presse-papier');
}

function exportJSON() {
  const data = {
    ip: <?=json_encode($ip)?>,
    timestamp: <?=json_encode(date('Y-m-d H:i:s'))?>,
    geo: <?=json_encode($data)?>,
    ports: <?=json_encode($ports)?>,
    dns: <?=json_encode($dns)?>,
    virustotal: <?=json_encode($vt)?>,
    abuseipdb: <?=json_encode($abuse)?>,
    shodan: <?=json_encode($shodan)?>,
    domains: <?=json_encode($domains)?>,
    emails: <?=json_encode($emails)?>,
    attribution: <?=json_encode($attribution)?>
  };
  const b = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(b);
  a.download = 'osint-<?=addslashes($ip)?>.json';
  a.click();
}

function exportPDF() {
  html2pdf().set({
    margin: 8,
    filename: 'osint-report-<?=addslashes($ip)?>.pdf',
    image: {type:'jpeg', quality:0.95},
    html2canvas: {scale:1.5, useCORS:true},
    jsPDF: {unit:'mm', format:'a4', orientation:'portrait'}
  }).from(document.querySelector('.wrap')).save();
}
</script>
</body>
</html>
