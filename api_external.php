<?php
// api_external.php - APIs خارجية للتحليل المتقدم

// ============================================
// 1. SecurityTrails API (نطاقات فرعية)
// ============================================
function getSecurityTrailsSubdomains($domain) {
    $apiKey = ''; // 🔑 سجلي مجاناً في securitytrails.com
    
    if (empty($apiKey)) return ['error' => 'مفتاح SecurityTrails غير مضبوط'];
    
    $url = "https://api.securitytrails.com/v1/domain/{$domain}/subdomains";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["APIKEY: $apiKey"]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode != 200) return ['error' => 'فشل جلب النطاقات الفرعية'];
    
    $data = json_decode($response, true);
    return [
        'domain' => $domain,
        'subdomains' => $data['subdomains'] ?? [],
        'count' => count($data['subdomains'] ?? [])
    ];
}

// ============================================
// 2. AlienVault OTX API (تهديدات)
// ============================================
function getAlienVaultThreats($ip) {
    $url = "https://otx.alienvault.com/api/v1/indicators/IPv4/{$ip}/general";
    $response = @file_get_contents($url);
    
    if (!$response) return ['error' => 'فشل جلب بيانات AlienVault'];
    
    $data = json_decode($response, true);
    
    return [
        'reputation' => $data['reputation'] ?? 0,
        'threat_count' => $data['pulse_info']['count'] ?? 0,
        'latest_threat' => $data['pulse_info']['pulses'][0]['name'] ?? null,
        'validation' => $data['validation'] ?? []
    ];
}

// ============================================
// 3. AbuseIPDB API (تقارير الإساءة)
// ============================================
function getAbuseIPDB($ip) {
    $apiKey = ''; // 🔑 سجلي مجاناً في abuseipdb.com
    
    if (empty($apiKey)) return ['error' => 'مفتاح AbuseIPDB غير مضبوط'];
    
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress={$ip}&maxAgeInDays=90";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Key: $apiKey", 
        "Accept: application/json"
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode != 200) return ['error' => 'فشل جلب بيانات AbuseIPDB'];
    
    $data = json_decode($response, true);
    
    if (!isset($data['data'])) return ['error' => 'لا توجد بيانات لهذا الـ IP'];
    
    return [
        'abuse_score' => $data['data']['abuseConfidenceScore'] ?? 0,
        'total_reports' => $data['data']['totalReports'] ?? 0,
        'last_reported' => $data['data']['lastReportedAt'] ?? null,
        'country' => $data['data']['countryCode'] ?? null,
        'isp' => $data['data']['isp'] ?? null,
        'usage_type' => $data['data']['usageType'] ?? null,
        'is_whitelisted' => $data['data']['isWhitelisted'] ?? false
    ];
}

// ============================================
// 4. VirusTotal API (سمعة IP) - اختياري
// ============================================
function getVirusTotal($ip) {
    $apiKey = ''; // 🔑 سجلي مجاناً في virustotal.com
    
    if (empty($apiKey)) return ['error' => 'مفتاح VirusTotal غير مضبوط'];
    
    $url = "https://www.virustotal.com/api/v3/ip_addresses/{$ip}";
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: $apiKey"]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $data = json_decode($response, true);
    
    if (!isset($data['data'])) return ['error' => 'IP غير موجود في VirusTotal'];
    $stats = $data['data']['attributes']['last_analysis_stats'];
    
    return [
        'malicious' => $stats['malicious'] ?? 0,
        'suspicious' => $stats['suspicious'] ?? 0,
        'harmless' => $stats['harmless'] ?? 0,
        'undetected' => $stats['undetected'] ?? 0
    ];
}

// ============================================
// 5. جلب كل البيانات مرة واحدة
// ============================================
function getAllExternalData($ip, $domain = null) {
    return [
        'threats' => getAlienVaultThreats($ip),
        'abuse' => getAbuseIPDB($ip),
        'virustotal' => getVirusTotal($ip),
        'subdomains' => $domain ? getSecurityTrailsSubdomains($domain) : null,
        'timestamp' => time()
    ];
}
?>