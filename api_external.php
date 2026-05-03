<?php
/**
 * api_external.php — Backend proxy pour les APIs externes
 * Retourne du JSON. Utilisé par le front en AJAX.
 *
 * Usage: api_external.php?action=vt&ip=1.2.3.4
 *        api_external.php?action=abuse&ip=1.2.3.4
 *        api_external.php?action=shodan&ip=1.2.3.4
 *        api_external.php?action=emails&domain=example.com
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// ── Config des clés API ────────────────────────────────────────────────────
define('VT_API_KEY',     '');          // Mettre votre clé VirusTotal ici
define('ABUSEIPDB_KEY',  '');          // Mettre votre clé AbuseIPDB ici
define('SHODAN_KEY',     '');          // Mettre votre clé Shodan ici
define('HUNTER_KEY',     '');          // Mettre votre clé Hunter.io ici

$action = $_GET['action'] ?? '';
$ip     = filter_var($_GET['ip'] ?? '', FILTER_VALIDATE_IP) ? $_GET['ip'] : '';
$domain = preg_replace('/[^a-z0-9.\-]/i', '', $_GET['domain'] ?? '');

if (!$ip && $action !== 'emails') {
    echo json_encode(['error' => 'IP invalide ou manquante']);
    exit;
}

// ── Rate limiting basique ─────────────────────────────────────────────────
$rateFile = sys_get_temp_dir() . '/osint_rate_' . md5($ip ?: $domain);
$rateData = file_exists($rateFile) ? json_decode(file_get_contents($rateFile), true) : ['count'=>0,'ts'=>time()];
if (time() - $rateData['ts'] < 60 && $rateData['count'] > 20) {
    echo json_encode(['error' => 'Rate limit atteint (max 20 req/min par IP)']);
    exit;
}
$rateData['count']++;
if (time() - $rateData['ts'] >= 60) { $rateData = ['count'=>1,'ts'=>time()]; }
file_put_contents($rateFile, json_encode($rateData));

// ── Mock helpers ─────────────────────────────────────────────────────────
function mockVT($ip) {
    srand(crc32($ip));
    $m = rand(0, 12); $s = rand(0, 8);
    $engines = ['Kaspersky','Sophos','CrowdStrike','Fortinet','BitDefender',
                'ESET','Symantec','Avast','McAfee','TrendMicro'];
    shuffle($engines);
    $detections = [];
    $cats = ['malware','c2','botnet','phishing','spam'];
    for ($i = 0; $i < $m; $i++)
        $detections[$engines[$i]] = $cats[array_rand($cats)];
    return [
        'source'         => 'demo',
        'malicious'      => $m,
        'suspicious'     => $s,
        'harmless'       => rand(55,80),
        'undetected'     => rand(3,10),
        'detections'     => $detections,
        'community_score'=> round(($m / 20) * -100),
        'last_analysis'  => date('Y-m-d', strtotime('-'.rand(1,30).' days')),
        'reputation'     => $m > 5 ? 'Malicious' : ($m > 0 ? 'Suspicious' : 'Clean'),
    ];
}

function mockAbuse($ip) {
    srand(crc32($ip.'abuse'));
    $score = rand(0, 100);
    $cats  = ['SSH Brute Force','Port Scan','Web Attack','DDoS','Spam','Phishing'];
    shuffle($cats);
    return [
        'source'        => 'demo',
        'abuse_score'   => $score,
        'total_reports' => rand(0, 450),
        'distinct_users'=> rand(1, 80),
        'last_reported' => date('Y-m-d', strtotime('-'.rand(0,14).' days')),
        'categories'    => array_slice($cats, 0, rand(1,3)),
        'usage_type'    => $score > 50 ? 'Data Center/Web Hosting' : 'ISP',
    ];
}

function mockShodan($ip) {
    srand(crc32($ip.'shodan'));
    $banners = ['Apache/2.4.51','nginx/1.18.0','OpenSSH_8.2p1',
                'Microsoft-IIS/10.0','lighttpd/1.4.55','PHP/8.0.3'];
    shuffle($banners);
    $vulns = ['CVE-2021-44228','CVE-2021-41773','CVE-2022-22965','CVE-2020-14882'];
    shuffle($vulns);
    return [
        'source'    => 'demo',
        'os'        => ['Ubuntu 20.04','CentOS 7','Windows Server 2019','Debian 11'][rand(0,3)],
        'banners'   => array_slice($banners, 0, rand(2,4)),
        'vulns'     => rand(0,1) ? array_slice($vulns, 0, rand(0,3)) : [],
        'last_scan' => date('Y-m-d H:i', strtotime('-'.rand(1,72).' hours')),
        'tags'      => rand(0,1) ? ['cloud','hosting'] : ['vpn','proxy'],
    ];
}

function mockEmails($domain) {
    if (empty($domain)) return ['source'=>'demo','emails'=>[]];
    $names = ['admin','security','abuse','contact','info','support','noc'];
    $emails = [];
    for ($i = 0; $i < rand(2,5); $i++) {
        $emails[] = ['email'=>$names[$i].'@'.$domain,'confidence'=>rand(60,99),'type'=>$i===0?'generic':'personal'];
    }
    return ['source'=>'demo','emails'=>$emails,'domain'=>$domain];
}

// ── Real API callers ──────────────────────────────────────────────────────
function realVT($ip) {
    $key = VT_API_KEY;
    if (empty($key)) return null;
    $ctx = stream_context_create(['http'=>['header'=>"x-apikey: $key\r\n",'timeout'=>8]]);
    $r = @file_get_contents("https://www.virustotal.com/api/v3/ip_addresses/$ip", false, $ctx);
    if (!$r) return null;
    $d = json_decode($r, true);
    $stats = $d['data']['attributes']['last_analysis_stats'] ?? [];
    $dets  = $d['data']['attributes']['last_analysis_results'] ?? [];
    $detMap = [];
    foreach ($dets as $eng => $res) {
        if ($res['category'] === 'malicious') $detMap[$eng] = $res['result'];
    }
    return [
        'source'         => 'virustotal',
        'malicious'      => $stats['malicious']   ?? 0,
        'suspicious'     => $stats['suspicious']  ?? 0,
        'harmless'       => $stats['harmless']    ?? 0,
        'undetected'     => $stats['undetected']  ?? 0,
        'detections'     => $detMap,
        'community_score'=> $d['data']['attributes']['total_votes']['harmless'] ?? 0,
        'last_analysis'  => date('Y-m-d', $d['data']['attributes']['last_analysis_date'] ?? time()),
        'reputation'     => ($stats['malicious']??0) > 5 ? 'Malicious' : (($stats['malicious']??0) > 0 ? 'Suspicious' : 'Clean'),
    ];
}

function realAbuse($ip) {
    $key = ABUSEIPDB_KEY;
    if (empty($key)) return null;
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90&verbose";
    $ctx = stream_context_create(['http'=>['header'=>"Key: $key\r\nAccept: application/json\r\n",'timeout'=>8]]);
    $r = @file_get_contents($url, false, $ctx);
    if (!$r) return null;
    $d = json_decode($r, true)['data'] ?? [];
    return [
        'source'        => 'abuseipdb',
        'abuse_score'   => $d['abuseConfidenceScore'] ?? 0,
        'total_reports' => $d['totalReports'] ?? 0,
        'distinct_users'=> $d['numDistinctUsers'] ?? 0,
        'last_reported' => $d['lastReportedAt'] ? date('Y-m-d', strtotime($d['lastReportedAt'])) : 'N/A',
        'categories'    => [],
        'usage_type'    => $d['usageType'] ?? 'Unknown',
    ];
}

// ── Router ────────────────────────────────────────────────────────────────
switch ($action) {
    case 'vt':
        $result = !empty(VT_API_KEY) ? (realVT($ip) ?? mockVT($ip)) : mockVT($ip);
        break;
    case 'abuse':
        $result = !empty(ABUSEIPDB_KEY) ? (realAbuse($ip) ?? mockAbuse($ip)) : mockAbuse($ip);
        break;
    case 'shodan':
        $result = mockShodan($ip);  // Shodan scan API n'est pas disponible gratuitement
        break;
    case 'emails':
        $result = mockEmails($domain);
        break;
    default:
        $result = ['error' => 'Action inconnue. Utiliser: vt, abuse, shodan, emails'];
}

echo json_encode($result, JSON_PRETTY_PRINT);
