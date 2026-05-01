<?php

// index.php - منصة OSINT متكاملة (Version 6.0 - MacOS Dock Style)

// ============================================
// 1. دوال جلب البيانات
// ============================================

function getIPInfo($ip) {
    $result = [];
    $geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=66846719");
    if ($geo) {
        $geoData = json_decode($geo, true);
        if ($geoData['status'] == 'success') {
            $result = [
                'country' => $geoData['country'] ?? 'غير معروف',
                'city' => $geoData['city'] ?? 'غير معروف',
                'isp' => $geoData['isp'] ?? 'غير معروف',
                'as' => $geoData['as'] ?? 'غير معروف',
                'lat' => $geoData['lat'] ?? 0,
                'lon' => $geoData['lon'] ?? 0,
                'hosting' => $geoData['hosting'] ?? false,
                'proxy' => $geoData['proxy'] ?? false
            ];
        }
    }
    return $result;
}

function getPorts($ip) {
    $ports = [21,22,23,25,53,80,110,443,8080,3306,3389];
    $open = [];
    foreach ($ports as $p) {
        if (@fsockopen($ip, $p, $err, $errs, 0.3)) {
            $open[] = $p;
        }
    }
    return $open;
}

function getDNSRecords($ip) {
    $result = [];
    $hostname = gethostbyaddr($ip);
    if ($hostname && $hostname != $ip) {
        $result['ptr'] = $hostname;
    }
    return $result;
}

// ===== جلب الإيميلات =====
function getEmails($domain) {
    $apiKey = ''; // ضعي مفتاحك من hunter.io
    $emails = [];
    
    if (!empty($apiKey)) {
        $url = "https://api.hunter.io/v2/domain-search?domain={$domain}&api_key={$apiKey}";
        $response = @file_get_contents($url);
        if ($response) {
            $data = json_decode($response, true);
            foreach ($data['data']['emails'] ?? [] as $email) {
                $emails[] = $email['value'];
            }
        }
    }
    return array_slice($emails, 0, 10);
}

// ============================================
// 2. معالجة البيانات
// ============================================

// start_time لتوقيت البحث
$start_time = microtime(true);

$ip = $_GET['ip'] ?? '';
$data = [];
$ports = [];
$dns = [];
$error = '';
$emails = [];

// معالجة إعادة ضبط التطبيق
if (isset($_GET['reset']) && $_GET['reset'] == '1') {
    if (file_exists('history.json')) unlink('history.json');
    if (file_exists('stats.json')) unlink('stats.json');
    $reset_msg = "✅ تم إعادة ضبط التطبيق بنجاح";
}

if (!empty($ip)) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $error = "IP غير صالح";
    } else {
        $data = getIPInfo($ip);
        $ports = getPorts($ip);
        $dns = getDNSRecords($ip);
        
        // جلب الإيميلات إذا توفر النطاق
        if (!empty($dns['ptr'])) {
            $domainParts = explode('.', $dns['ptr']);
            $domain = implode('.', array_slice($domainParts, -2));
            $emails = getEmails($domain);
        }
    }
}

// حساب نسبة الخطورة
$threatScore = 0;
if ($data['hosting'] ?? false) $threatScore += 40;
if ($data['proxy'] ?? false) $threatScore += 30;
$threatScore += count($ports) * 2;
if ($threatScore > 100) $threatScore = 100;

$riskLevel = 'منخفض';
$riskColor = '#22c55e';
if ($threatScore > 50) {
    $riskLevel = 'مرتفع';
    $riskColor = '#ef4444';
} elseif ($threatScore > 25) {
    $riskLevel = 'متوسط';
    $riskColor = '#eab308';
}

// ===== إحصائيات البحث =====
$statsFile = 'stats.json';
$stats = [];
if (file_exists($statsFile)) {
    $stats = json_decode(file_get_contents($statsFile), true);
}

// عداد الزوار
$stats['visitors'] = ($stats['visitors'] ?? 0) + 1;

if (!empty($ip) && !$error && !empty($data)) {
    $stats['total_searches'] = ($stats['total_searches'] ?? 0) + 1;
    if (!isset($stats['ips'][$ip])) {
        $stats['ips'][$ip] = 0;
    }
    $stats['ips'][$ip]++;
    $stats['last_search'] = date('Y-m-d H:i:s');
    file_put_contents($statsFile, json_encode($stats, JSON_PRETTY_PRINT));
}
// ===== سجل البحث =====
$historyFile = 'history.json';
$history = [];
if (file_exists($historyFile)) {
    $history = json_decode(file_get_contents($historyFile), true);
}

if (!empty($ip) && !$error && !empty($data)) {
    $exists = false;
    foreach ($history as &$h) {
        if ($h['ip'] == $ip) {
            $exists = true;
            $h['last_seen'] = date('Y-m-d H:i:s');
            break;
        }
    }
    if (!$exists) {
        $history[] = [
            'ip' => $ip,
            'country' => $data['country'] ?? 'غير معروف',
            'hosting' => $data['hosting'] ?? false,
            'proxy' => $data['proxy'] ?? false,
            'first_seen' => date('Y-m-d H:i:s'),
            'last_seen' => date('Y-m-d H:i:s')
        ];
        file_put_contents($historyFile, json_encode($history, JSON_PRETTY_PRINT));
    }
}

// ===== حذف من السجل =====
if (isset($_GET['delete'])) {
    $deleteIP = $_GET['delete'];
    $history = array_filter($history, function($item) use ($deleteIP) {
        return $item['ip'] != $deleteIP;
    });
    file_put_contents($historyFile, json_encode(array_values($history), JSON_PRETTY_PRINT));
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

// توقيت البحث
$end_time = microtime(true);
$execution_time = round(($end_time - $start_time) * 1000, 2);

// نصائح عشوائية
$tips = [
    "🔍 استخدمي IPs مختلفة للحصول على صورة كاملة",
    "🛡️ تحقق دائماً من قوائم الحظر قبل الثقة بأي IP",
    "📊 السجل يحتفظ بآخر 100 IP بحثت عنها",
    "🗺️ يمكنك فتح الخريطة في Google Maps بنقرة واحدة",
    "📧 الإيميلات تظهر فقط إذا كان الـ IP عنده نطاق معروف",
    "⚡ كلما زادت المنافذ المفتوحة، زادت نسبة الخطورة"
];
$randomTip = $tips[array_rand($tips)];
?>
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>OSINT Infrastructure Mapper Pro</title>
    <!-- Font Awesome 6 (للأيقونات) -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #e2e8f0;
            padding: 20px;
            padding-bottom: 100px; /* مساحة للـ Dock */
            transition: all 0.3s ease;
        }
        /* وضع النهار */
        body.light-mode {
            background: #f1f5f9;
            color: #0f172a;
        }
        body.light-mode .box {
            background: #ffffff;
            border-color: #e2e8f0;
        }
        body.light-mode .box:hover {
            border-color: #0891b2;
        }
        body.light-mode .info {
            border-bottom-color: #e2e8f0;
        }
        body.light-mode .badge {
            background: #f1f5f9;
        }
        body.light-mode .risk-low { background: #dcfce7; color: #166534; }
        body.light-mode .risk-medium { background: #fef3c7; color: #92400e; }
        body.light-mode .risk-high { background: #fee2e2; color: #991b1b; }
        .container { max-width: 1200px; margin: 0 auto; }
        .box {
            background: #1e293b;
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid #334155;
            transition: 0.3s;
        }
        .box:hover { border-color: #00ffff; box-shadow: 0 0 15px rgba(0,255,255,0.1); }
        .title { color: #00ffff; text-align: center; font-size: 32px; margin-bottom: 10px; }
        .subtitle { text-align: center; color: #94a3b8; margin-bottom: 25px; }
        input, button {
            padding: 12px 16px;
            border-radius: 12px;
            border: none;
            font-size: 16px;
        }
        input {
            background: #0f172a;
            border: 1px solid #334155;
            color: white;
            flex: 1;
            outline: none;
        }
        input:focus { border-color: #00ffff; }
        button {
            background: #0891b2;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }
        button:hover { background: #0e7490; transform: scale(1.02); }
        .flex { display: flex; gap: 12px; flex-wrap: wrap; }
        .info {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #334155;
        }
        .badge {
            background: #0f172a;
            border: 1px solid #00ffff;
            border-radius: 20px;
            padding: 5px 12px;
            display: inline-block;
            margin: 4px;
        }
        canvas {
            background: #0a0e1a;
            border-radius: 16px;
            width: 100%;
            height: auto;
            margin-top: 20px;
        }
        .risk-low { background: #065f46; color: #86efac; display: inline-block; padding: 4px 12px; border-radius: 20px; }
        .risk-medium { background: #854d0e; color: #fde68a; display: inline-block; padding: 4px 12px; border-radius: 20px; }
        .risk-high { background: #7f1a1a; color: #fca5a5; display: inline-block; padding: 4px 12px; border-radius: 20px; }
        .progress-bar {
            background: #334155;
            height: 25px;
            border-radius: 12px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            border-radius: 12px;
            transition: width 0.5s ease;
        }
        .btn-group { display: flex; gap: 10px; justify-content: center; margin-bottom: 20px; flex-wrap: wrap; }
        .btn-copy { background: #3b82f6; }
        .btn-print { background: #ef4444; }
        .btn-export { background: #8b5cf6; }
        .btn-pdf { background: #dc2626; }

        /* ===== MacOS Dock Style ===== */
        .mac-dock {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            gap: 12px;
            background: rgba(30, 30, 40, 0.85);
            backdrop-filter: blur(20px);
            padding: 12px 20px;
            border-radius: 50px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            z-index: 1000;
        }

        body.light-mode .mac-dock {
            background: rgba(255, 255, 255, 0.85);
            border: 1px solid rgba(0, 0, 0, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .dock-icon {
            position: relative;
            transition: all 0.2s ease;
        }

        .dock-icon a, .dock-icon button {
            display: flex;
            justify-content: center;
            align-items: center;
            width: 50px;
            height: 50px;
            border-radius: 30px;
            background: rgba(255, 255, 255, 0.15);
            color: white;
            font-size: 24px;
            text-decoration: none;
            border: none;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        body.light-mode .dock-icon a,
        body.light-mode .dock-icon button {
            background: rgba(0, 0, 0, 0.08);
            color: #1e293b;
        }

        /* تأثير الـ Hover (زيادة الحجم + تحريك للأعلى) */
        .dock-icon:hover {
            transform: translateY(-8px) scale(1.3);
        }

        .dock-icon:hover a,
        .dock-icon:hover button {
            background: #0891b2;
            color: white;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        /* التولتيب (tooltip) */
        .tooltip {
            position: absolute;
            bottom: 70px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s;
            font-weight: normal;
        }

        .dock-icon:hover .tooltip {
            opacity: 1;
        }

        /* للأجهزة الصغيرة (جوال) */
        @media (max-width: 768px) {
            .mac-dock {
                gap: 6px;
                padding: 8px 12px;
                bottom: 10px;
            }
            .dock-icon a, .dock-icon button {
                width: 40px;
                height: 40px;
                font-size: 18px;
            }
            .dock-icon:hover {
                transform: translateY(-5px) scale(1.2);
            }
            .tooltip {
                bottom: 55px;
                font-size: 10px;
                padding: 4px 8px;
            }
            body {
                padding-bottom: 80px;
            }
        }

        @media print {
            body { background: white; padding: 0; }
            .box { background: white; color: black; border: 1px solid #ddd; }
            .title { color: #0891b2; }
            .btn-group { display: none; }
            .mac-dock { display: none; }
            button { display: none; }
            canvas { background: white; border: 1px solid #ddd; }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
</head>
<body>
<div class="container">

    <!-- ========== MacOS Dock Style Navbar ========== -->
    <div class="mac-dock">
        <div class="dock-icon">
            <a href="?">
                <i class="fas fa-home"></i>
                <span class="tooltip">الرئيسية</span>
            </a>
        </div>
        <div class="dock-icon">
            <a href="dashboard.php">
                <i class="fas fa-chart-line"></i>
                <span class="tooltip">Dashboard</span>
            </a>
        </div>
        <div class="dock-icon">
            <a href="compare.php">
                <i class="fas fa-code-branch"></i>
                <span class="tooltip">مقارنة</span>
            </a>
        </div>
        <div class="dock-icon">
            <a href="about.php">
                <i class="fas fa-info-circle"></i>
                <span class="tooltip">عن</span>
            </a>
        </div>
        <div class="dock-icon">
            <a href="clear-data.php" onclick="return confirm('⚠️ هل أنت متأكدة؟')">
                <i class="fas fa-trash-alt"></i>
                <span class="tooltip">مسح</span>
            </a>
        </div>
        <div class="dock-icon">
            <button onclick="toggleTheme()" class="theme-btn">
                <i class="fas fa-moon"></i>
                <span class="tooltip">الوضع</span>
            </button>
        </div>
        <div class="dock-icon">
            <a href="?reset=1" onclick="return confirm('⚠️ هل أنت متأكدة؟ هذا سيحذف كل السجل والإحصائيات نهائياً!')">
                <i class="fas fa-sync-alt"></i>
                <span class="tooltip">إعادة ضبط</span>
            </a>
        </div>
        <?php if (!empty($ip) && !empty($data)): ?>
            <?php if ($data['lat'] != 0 && $data['lon'] != 0): ?>
            <div class="dock-icon">
                <a href="https://www.google.com/maps?q=<?php echo $data['lat']; ?>,<?php echo $data['lon']; ?>" target="_blank">
                    <i class="fas fa-map-marker-alt"></i>
                    <span class="tooltip">خرائط</span>
                </a>
            </div>
            <?php endif; ?>
            <div class="dock-icon">
                <a href="?">
                    <i class="fas fa-times-circle"></i>
                    <span class="tooltip">مسح البحث</span>
                </a>
            </div>
            <div class="dock-icon">
                <button onclick="window.scrollTo({top: 0, behavior: 'smooth'});">
                    <i class="fas fa-arrow-up"></i>
                    <span class="tooltip">أعلى</span>
                </button>
            </div>
        <?php endif; ?>
    </div>

    <!-- رسالة إعادة الضبط -->
    <?php if (isset($reset_msg)): ?>
    <div class="box" style="background: #065f46; text-align: center; border-color: #22c55e;">
        <p style="color: #86efac;"><?php echo $reset_msg; ?></p>
    </div>
    <?php endif; ?>

    <!-- ========== نصيحة عشوائية ========== -->
    <div class="box" style="background: #0f172a; text-align: center; border-color: #8b5cf6;">
        <p style="color: #c4b5fd;">💡 <?php echo $randomTip; ?></p>
    </div>

    <!-- ========== العنوان وشريط البحث ========== -->
    <div class="box">
        <div class="title">🕵️ OSINT Infrastructure Mapper Pro</div>
        <div class="subtitle">تحليل البنية التحتية | معلومات حقيقية + خرائط Google</div>

        <form method="GET" class="flex">
            <input type="text" name="ip" placeholder="أدخل IP... مثال: 8.8.8.8" value="<?php echo htmlspecialchars($ip); ?>">
            <button type="submit">🔍 تحقيق</button>
        </form>
    </div>

    <?php if ($error): ?>
    <div class="box" style="background: #7f1a1a; border-color: #ef4444;">
        <p style="color: #fca5a5;">⚠️ <?php echo $error; ?></p>
    </div>
    <?php endif; ?>

    <?php if (!empty($ip) && !$error && !empty($data)): ?>

    <!-- ========== أزرار التحكم ========== -->
    <div class="btn-group">
        <button onclick="copyResults()" class="btn-copy">📋 نسخ النتائج</button>
        <button onclick="window.print()" class="btn-print">🖨️ طباعة / PDF</button>
        <button onclick="exportData()" class="btn-export">📥 تصدير JSON</button>
        <button onclick="exportToPDF()" class="btn-pdf">📄 تصدير PDF</button>
    </div>

    <!-- ========== وقت البحث ========== -->
    <div class="box">
        <div class="info"><span>⏱️ وقت البحث</span><span><?php echo $execution_time; ?> ميلي ثانية</span></div>
        <div class="info"><span>👁️ عدد زوار التطبيق</span><span><?php echo $stats['visitors'] ?? 0; ?></span></div>
    </div>

    <!-- ========== المعلومات الأساسية ========== -->
    <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">📍 الموقع الجغرافي</h2>
        <div class="info"><span>🌍 البلد</span><span><?php echo $data['country']; ?></span></div>
        <div class="info"><span>🏙️ المدينة</span><span><?php echo $data['city']; ?></span></div>
        <div class="info"><span>🏢 مزود الخدمة (ISP)</span><span style="color: #00ffff;"><?php echo $data['isp']; ?></span></div>
        <div class="info"><span>🔄 نظام AS</span><span><?php echo $data['as']; ?></span></div>
        <div class="info"><span>🛡️ خادم استضافة</span><span><?php echo $data['hosting'] ? 'نعم ⚠️' : 'لا ✅'; ?></span></div>
        <div class="info"><span>🔒 وكيل Proxy</span><span><?php echo $data['proxy'] ? 'نعم ⚠️' : 'لا ✅'; ?></span></div>
        <?php if (!empty($dns['ptr'])): ?>
        <div class="info"><span>🖥️ Reverse DNS</span><span><?php echo $dns['ptr']; ?></span></div>
        <?php endif; ?>
    </div>

    <!-- ========== زر فتح الخريطة الحقيقية (Google Maps) ========== -->
    <?php if ($data['lat'] != 0 && $data['lon'] != 0): ?>
    <div class="box" style="text-align: center;">
        <h2 style="color: #00ffff; margin-bottom: 15px;">🗺️ فتح الخريطة الحقيقية</h2>
        <div style="display: flex; gap: 15px; justify-content: center; flex-wrap: wrap;">
            <a href="https://www.google.com/maps?q=<?php echo $data['lat']; ?>,<?php echo $data['lon']; ?>" 
               target="_blank"
               style="background: #1e293b; border: 1px solid #3b82f6; border-radius: 40px; padding: 12px 25px; text-decoration: none; color: #60a5fa; display: inline-flex; align-items: center; gap: 10px; transition: 0.3s;">
                <span style="font-size: 20px;">🗺️</span> Google Maps
            </a>
            <a href="https://www.openstreetmap.org/?mlat=<?php echo $data['lat']; ?>&mlon=<?php echo $data['lon']; ?>&zoom=12" 
               target="_blank"
               style="background: #1e293b; border: 1px solid #22c55e; border-radius: 40px; padding: 12px 25px; text-decoration: none; color: #86efac; display: inline-flex; align-items: center; gap: 10px; transition: 0.3s;">
                <span style="font-size: 20px;">🌍</span> OpenStreetMap
            </a>
            <a href="https://www.bing.com/maps?cp=<?php echo $data['lat']; ?>~<?php echo $data['lon']; ?>&lvl=12" 
               target="_blank"
               style="background: #1e293b; border: 1px solid #ef4444; border-radius: 40px; padding: 12px 25px; text-decoration: none; color: #fca5a5; display: inline-flex; align-items: center; gap: 10px; transition: 0.3s;">
                <span style="font-size: 20px;">🗺️</span> Bing Maps
            </a>
        </div>
        <p style="color: #94a3b8; font-size: 12px; margin-top: 15px;">
            📍 الإحداثيات: <?php echo $data['lat']; ?>, <?php echo $data['lon']; ?>
        </p>
    </div>
    <?php endif; ?>

    <!-- ========== المنافذ المفتوحة ========== -->
    <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">🔌 المنافذ المفتوحة</h2>
        <div>
            <?php if (empty($ports)): ?>
                <p>✅ لا توجد منافذ شائعة مفتوحة</p>
            <?php else: ?>
                <?php foreach ($ports as $p): ?>
                    <span class="badge">🔓 المنفذ <?php echo $p; ?></span>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- ========== مقياس التهديدات ========== -->
    <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">📊 مقياس التهديدات (Threat Meter)</h2>
        <div class="info"><span>🎲 نسبة الخطورة الإجمالية</span>
            <span class="<?php echo ($threatScore > 50) ? 'risk-high' : (($threatScore > 25) ? 'risk-medium' : 'risk-low'); ?>">
                <?php echo $threatScore; ?>% - <?php echo $riskLevel; ?>
            </span>
        </div>
        <div class="progress-bar">
            <div class="progress-fill" style="width: <?php echo $threatScore; ?>%; background: linear-gradient(90deg, #22c55e, #eab308, #ef4444);"></div>
        </div>
    </div>

    <!-- ========== الإيميلات المكتشفة ========== -->
    <?php if (!empty($emails)): ?>
    <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">📧 الإيميلات المرتبطة بالنطاق</h2>
        <div style="display: flex; flex-direction: column; gap: 8px;">
            <?php foreach ($emails as $email): ?>
                <div style="background: #0f172a; border: 1px solid #a855f7; border-radius: 12px; padding: 10px; display: flex; justify-content: space-between; align-items: center;">
                    <span>✉️ <?php echo htmlspecialchars($email); ?></span>
                    <button onclick="copyToClipboard('<?php echo $email; ?>')" style="background: #3b82f6; padding: 4px 12px; border-radius: 8px; font-size: 12px;">📋 نسخ</button>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- ========== سجل البحث مع زر الحذف ========== -->
     <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">📜 سجل البحث</h2>
        <div style="display: flex; flex-wrap: wrap; gap: 10px; max-height: 200px; overflow-y: auto;">
            <?php foreach (array_reverse($history) as $h): ?>
                <div style="display: inline-flex; align-items: center; gap: 5px;">
                    <a href="?ip=<?php echo $h['ip']; ?>" style="background: #0f172a; border: 1px solid #00ffff; border-radius: 20px; padding: 5px 12px; text-decoration: none; color: #00ffff; font-size: 13px;">
                        <?php echo $h['ip']; ?> (<?php echo $h['country']; ?>)
                    </a>
                    <a href="?delete=<?php echo $h['ip']; ?>" style="background: #7f1a1a; border-radius: 20px; padding: 5px 10px; text-decoration: none; color: #fca5a5; font-size: 11px;" onclick="return confirm('تحذفي <?php echo $h['ip']; ?> من السجل؟')">✖️</a>
                </div>
            <?php endforeach; ?>
            <?php if (empty($history)) echo '<p style="color:#94a3b8;">ما زال ما بحثتي على تا IP</p>'; ?>
        </div>
    </div>

    <!-- ========== إحصائيات البحث ========== -->
    <div class="box">
        <h2 style="color: #00ffff; margin-bottom: 15px;">📊 إحصائيات البحث</h2>
        <div class="info"><span>🔍 عدد عمليات البحث الإجمالية</span><span><?php echo $stats['total_searches'] ?? 0; ?></span></div>
        <div class="info"><span>🌍 عدد الـ IPs الفريدة</span><span><?php echo count($stats['ips'] ?? []); ?></span></div>
        <div class="info"><span>🕐 آخر بحث</span><span><?php echo $stats['last_search'] ?? 'لا يوجد'; ?></span></div>
    </div>

    <!-- ========== رسم Maltego Graph ========== -->
    <div class="box">
        <h2 style="color: #00ffff; text-align: center; margin-bottom: 15px;">🕸️ Maltego Graph - خريطة البنية التحتية</h2>
        <canvas id="myCanvas" width="900" height="450"></canvas>
    </div>

    <?php elseif (!empty($ip) && !$error && empty($data)): ?>
    <div class="box" style="background: #854d0e;">
        <p style="text-align: center;">⏳ جاري جلب المعلومات...</p>
    </div>
    <?php endif; ?>

    <!-- ========== الفوتر ========== -->
    <footer style="text-align: center; color: #64748b; font-size: 12px; margin-top: 20px; padding: 20px; border-top: 1px solid #334155;">
        🔍 OSINT Infrastructure Mapper Pro | بيانات حقيقية من ip-api.com | خرائط Google
    </footer>
</div>

<script>
// ========== 1. رسم Maltego Graph ==========
(function() {
    var canvas = document.getElementById('myCanvas');
    if (!canvas) return;

    canvas.width = 900;
    canvas.height = 450;
    var ctx = canvas.getContext('2d');
    var w = canvas.width, h = canvas.height;
    var cx = w/2, cy = h/2;

    var ip = '<?php echo addslashes($ip); ?>';
    var country = '<?php echo addslashes($data['country']); ?>';
    var isp = '<?php echo addslashes(substr($data['isp'], 0, 22)); ?>';
    var risk = '<?php echo $riskLevel; ?>';
    var riskColor = '<?php echo $riskColor; ?>';
    var portsList = <?php echo json_encode($ports); ?>;

    ctx.fillStyle = '#0a0e1a';
    ctx.fillRect(0, 0, w, h);

    // شبكة
    ctx.strokeStyle = '#00ffff15';
    ctx.lineWidth = 0.5;
    for(var i = -400; i <= 400; i += 50) {
        ctx.beginPath(); ctx.moveTo(cx + i, 0); ctx.lineTo(cx + i, h); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0, cy + i); ctx.lineTo(w, cy + i); ctx.stroke();
    }
    var nodes = [
        { x: cx, y: cy, label: ip, color: '#00ffff', r: 26 },
        { x: cx - 200, y: cy - 80, label: country, color: '#4ade80', r: 20 },
        { x: cx + 200, y: cy - 80, label: isp, color: '#eab308', r: 20 },
        { x: cx, y: cy + 150, label: risk, color: riskColor, r: 20 }
    ];

    for(var i=0; i<Math.min(portsList.length, 4); i++) {
        nodes.push({
            x: cx - 150 + (i * 100),
            y: cy + 210,
            label: 'P'+portsList[i],
            color: '#a855f7',
            r: 16
        });
    }

    var main = nodes[0];
    for(var i=1; i<nodes.length; i++) {
        var to = nodes[i];
        ctx.beginPath();
        ctx.moveTo(main.x, main.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = to.color;
        ctx.lineWidth = 2;
        ctx.stroke();

        var ang = Math.atan2(to.y - main.y, to.x - main.x);
        var ax = to.x - 15 * Math.cos(ang);
        var ay = to.y - 15 * Math.sin(ang);
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - 6 * Math.cos(ang - Math.PI/6), ay - 6 * Math.sin(ang - Math.PI/6));
        ctx.lineTo(ax - 6 * Math.cos(ang + Math.PI/6), ay - 6 * Math.sin(ang + Math.PI/6));
        ctx.fillStyle = to.color;
        ctx.fill();
    }

    for(var i=0; i<nodes.length; i++) {
        var n = nodes[i];
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
        ctx.fillStyle = n.color;
        ctx.fill();
        ctx.strokeStyle = '#fff';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.font = 'bold 13px Segoe UI';
        ctx.fillStyle = '#fff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(n.label, n.x, n.y);
    }
})();

// ========== 2. دوال التحكم ==========
function copyResults() {
    var text = '';
    text += '🔍 تقرير OSINT للـ IP: <?php echo addslashes($ip); ?>\n';
    text += '═══════════════════════════════════════\n';
    text += '📍 الموقع الجغرافي:\n';
    text += '   🌍 البلد: <?php echo addslashes($data['country']); ?>\n';
    text += '   🏙️ المدينة: <?php echo addslashes($data['city']); ?>\n';
    text += '   🏢 ISP: <?php echo addslashes($data['isp']); ?>\n';
    text += '   🔄 AS: <?php echo addslashes($data['as']); ?>\n';
    text += '   🛡️ Hosting: <?php echo $data['hosting'] ? 'نعم' : 'لا'; ?>\n';
    text += '   🔒 Proxy: <?php echo $data['proxy'] ? 'نعم' : 'لا'; ?>\n';
    text += '\n🔌 المنافذ المفتوحة: <?php echo implode(", ", $ports) ?: "لا توجد"; ?>\n';
    text += '\n📊 نسبة الخطورة: <?php echo $threatScore; ?>% - <?php echo $riskLevel; ?>\n';
    text += '═══════════════════════════════════════\n';
    text += '📅 التاريخ: <?php echo date('Y-m-d H:i:s'); ?>\n';
    navigator.clipboard.writeText(text);
    alert('✅ تم نسخ التقرير');
}

function exportData() {
    var data = {
        ip: '<?php echo addslashes($ip); ?>',
        geo: {
            country: '<?php echo addslashes($data['country']); ?>',
            city: '<?php echo addslashes($data['city']); ?>',
            isp: '<?php echo addslashes($data['isp']); ?>',
            as: '<?php echo addslashes($data['as']); ?>',
            hosting: <?php echo $data['hosting'] ? 'true' : 'false'; ?>,
            proxy: <?php echo $data['proxy'] ? 'true' : 'false'; ?>
        },
        openPorts: <?php echo json_encode($ports); ?>,
        threatScore: <?php echo $threatScore; ?>,
        riskLevel: '<?php echo $riskLevel; ?>',
        timestamp: '<?php echo date('Y-m-d H:i:s'); ?>'
    };
    var blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'osint-report-<?php echo $ip; ?>.json';
    link.click();
    alert('✅ تم تصدير التقرير');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    alert('✅ تم نسخ: ' + text);
}

function exportToPDF() {
    const element = document.querySelector('.container');
    html2pdf().set({
        margin: 10,
        filename: 'osint-report-<?php echo $ip; ?>.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2 },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
    }).from(element).save();
}

function toggleTheme() {
    document.body.classList.toggle('light-mode');
    var themeIcon = document.querySelector('.theme-btn i');
    if (document.body.classList.contains('light-mode')) {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    } else {
        themeIcon.classList.remove('fa-sun');
        themeIcon.classList.add('fa-moon');
    }
    localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
}

// تحميل الثيم المحفوظ
if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light-mode');
    var themeIcon = document.querySelector('.theme-btn i');
    if (themeIcon) {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    }
}

// إشعار عند انتهاء البحث
<?php if (!empty($ip) && !$error && !empty($data)): ?>
if (Notification.permission !== 'granted') {
    Notification.requestPermission();
}
if (Notification.permission === 'granted') {
    new Notification('✅ اكتمل التحقيق', {
        body: 'تم تحليل الـ IP: <?php echo addslashes($ip); ?>',
        icon: 'https://cdn-icons-png.flaticon.com/512/1483/1483846.png'
    });
}
<?php endif; ?>
</script>

</body>
</html>

