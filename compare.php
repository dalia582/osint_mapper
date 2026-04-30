<?php
// compare.php - مقارنة بين عدة IPs

function getIPInfo($ip) {
    $geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=66846719");
    if ($geo) {
        $geoData = json_decode($geo, true);
        if ($geoData['status'] == 'success') {
            return [
                'country' => $geoData['country'] ?? 'غير معروف',
                'city' => $geoData['city'] ?? 'غير معروف',
                'isp' => $geoData['isp'] ?? 'غير معروف',
                'hosting' => $geoData['hosting'] ?? false,
                'proxy' => $geoData['proxy'] ?? false
            ];
        }
    }
    return [];
}

$ips = $_GET['ips'] ?? '';
$ipList = [];
$results = [];

if (!empty($ips)) {
    $ipList = explode(',', $ips);
    foreach ($ipList as $ip) {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $results[$ip] = getIPInfo($ip);
        }
    }
}
?>
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>مقارنة IPs - OSINT</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white p-6">
<div class="container mx-auto">

    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl text-cyan-400">🔍 مقارنة بين IPs</h1>
        <a href="index.php" class="bg-cyan-600 px-4 py-2 rounded-xl hover:bg-cyan-500">🏠 العودة للرئيسية</a>
    </div>

    <div class="bg-gray-800 p-6 rounded-xl mb-8">
        <form method="GET" class="flex gap-4">
            <input type="text" name="ips" placeholder="أدخل IPs مفصولة بفواصل... مثال: 8.8.8.8,1.1.1.1,4.4.4.4" 
                   value="<?php echo htmlspecialchars($ips); ?>"
                   class="flex-1 p-3 bg-gray-700 rounded-xl border border-gray-600 focus:border-cyan-400 outline-none">
            <button type="submit" class="bg-cyan-600 px-6 py-3 rounded-xl hover:bg-cyan-500">📊 مقارنة</button>
        </form>
    </div>

    <?php if (!empty($results)): ?>
    <div class="bg-gray-800 p-6 rounded-xl overflow-x-auto">
        <table class="w-full text-center">
            <thead>
                <tr class="border-b border-gray-700">
                    <th class="p-3">🌍 IP</th>
                    <th class="p-3">🇨🇳 البلد</th>
                    <th class="p-3">🏙️ المدينة</th>
                    <th class="p-3">🏢 ISP</th>
                    <th class="p-3">🛡️ Hosting</th>
                    <th class="p-3">🔒 Proxy</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($results as $ip => $data): ?>
                <tr class="border-b border-gray-700">
                    <td class="p-3"><a href="index.php?ip=<?php echo $ip; ?>" class="text-cyan-400"><?php echo $ip; ?></a></td>
                    <td class="p-3"><?php echo $data['country']; ?></td>
                    <td class="p-3"><?php echo $data['city']; ?></td>
                    <td class="p-3"><?php echo $data['isp']; ?></td>
                    <td class="p-3"><?php echo $data['hosting'] ? '⚠️ نعم' : '✅ لا'; ?></td>
                    <td class="p-3"><?php echo $data['proxy'] ? '⚠️ نعم' : '✅ لا'; ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

</div>
</body>
</html>