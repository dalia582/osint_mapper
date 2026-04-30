<?php
// dashboard.php - لوحة تحكم منفصلة

$historyFile = 'history.json';
$statsFile = 'stats.json';

$history = file_exists($historyFile) ? json_decode(file_get_contents($historyFile), true) : [];
$stats = file_exists($statsFile) ? json_decode(file_get_contents($statsFile), true) : [];

$totalIPs = count($history);
$hostingCount = 0;
$proxyCount = 0;
$countries = [];

foreach ($history as $h) {
    $countries[$h['country']] = ($countries[$h['country']] ?? 0) + 1;
    if ($h['hosting'] ?? false) $hostingCount++;
    if ($h['proxy'] ?? false) $proxyCount++;
}
?>
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>لوحة التحكم - OSINT</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            font-family: 'Segoe UI', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-900 text-white p-6">
<div class="container mx-auto">

    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl text-cyan-400">📊 لوحة تحليل التهديدات</h1>
        <a href="index.php" class="bg-cyan-600 px-4 py-2 rounded-xl hover:bg-cyan-500">🏠 العودة للرئيسية</a>
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div class="bg-gray-800 p-6 rounded-xl text-center">
            <div class="text-4xl text-cyan-400">🔍</div>
            <div class="text-2xl font-bold"><?php echo $totalIPs; ?></div>
            <div class="text-gray-400">IP تم تحليلها</div>
        </div>
        <div class="bg-gray-800 p-6 rounded-xl text-center">
            <div class="text-4xl text-yellow-400">🛡️</div>
            <div class="text-2xl font-bold"><?php echo $hostingCount; ?></div>
            <div class="text-gray-400">خوادم استضافة</div>
        </div>
        <div class="bg-gray-800 p-6 rounded-xl text-center">
            <div class="text-4xl text-red-400">🔒</div>
            <div class="text-2xl font-bold"><?php echo $proxyCount; ?></div>
            <div class="text-gray-400">Proxy/VPN</div>
        </div>
        <div class="bg-gray-800 p-6 rounded-xl text-center">
            <div class="text-4xl text-green-400">🌍</div>
            <div class="text-2xl font-bold"><?php echo count($countries); ?></div>
            <div class="text-gray-400">دول مختلفة</div>
        </div>
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="bg-gray-800 p-6 rounded-xl">
            <h2 class="text-xl text-cyan-400 mb-4">🌍 توزيع الـ IPs حسب البلد</h2>
            <canvas id="countryChart"></canvas>
        </div>
        <div class="bg-gray-800 p-6 rounded-xl">
            <h2 class="text-xl text-cyan-400 mb-4">⚠️ مستوى التهديدات</h2>
            <canvas id="threatChart"></canvas>
        </div>
    </div>
    
    <div class="bg-gray-800 p-6 rounded-xl mt-6">
        <h2 class="text-xl text-cyan-400 mb-4">📋 آخر 10 IPs تم البحث عنها</h2>
        <div class="space-y-2">
            <?php foreach (array_slice(array_reverse($history), 0, 10) as $h): ?>
                <div class="flex justify-between items-center p-2 bg-gray-700 rounded-lg">
                    <span><?php echo $h['ip']; ?></span>
                    <span><?php echo $h['country']; ?></span>
                    <span class="text-xs text-gray-400"><?php echo $h['last_seen']; ?></span>
                    <a href="index.php?ip=<?php echo $h['ip']; ?>" class="text-cyan-400 text-sm">🔍 عرض</a>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    
</div>

<script>
const ctx1 = document.getElementById('countryChart').getContext('2d');
new Chart(ctx1, {
    type: 'pie',
    data: {
        labels: <?php echo json_encode(array_keys($countries)); ?>,
        datasets: [{ data: <?php echo json_encode(array_values($countries)); ?>, backgroundColor: ['#00ffff','#4ade80','#eab308','#a855f7','#f97316'] }]
    }
});
const ctx2 = document.getElementById('threatChart').getContext('2d');
new Chart(ctx2, {
    type: 'doughnut',
    data: {
        labels: ['خوادم استضافة', 'Proxy/VPN', 'عادي'],
        datasets: [{ data: [<?php echo $hostingCount; ?>, <?php echo $proxyCount; ?>, <?php echo $totalIPs - $hostingCount - $proxyCount; ?>], backgroundColor: ['#eab308','#ef4444','#22c55e'] }]
    }
});
</script>
</body>
</html>