<?php
// about.php - معلومات عن التطبيق
?>
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>عن التطبيق - OSINT</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white p-6">
<div class="container mx-auto max-w-3xl">

    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl text-cyan-400">ℹ️ عن التطبيق</h1>
        <a href="index.php" class="bg-cyan-600 px-4 py-2 rounded-xl hover:bg-cyan-500">🏠 العودة للرئيسية</a>
    </div>

    <div class="bg-gray-800 p-8 rounded-xl space-y-6">
        <div class="text-center">
            <span class="text-6xl">🕵️</span>
            <h2 class="text-2xl text-cyan-400 mt-3">OSINT Infrastructure Mapper</h2>
            <p class="text-gray-400 mt-2">Version 6.0</p>
        </div>

        <div class="border-t border-gray-700 pt-6">
            <h3 class="text-xl text-cyan-400 mb-3">🎯 الهدف من التطبيق</h3>
            <p class="text-gray-300">تحليل البنية التحتية للمهاجمين باستخدام مصادر مفتوحة (OSINT) ورسم خريطة العلاقات بين الـ IPs والمزودين والمواقع.</p>
        </div>

        <div class="border-t border-gray-700 pt-6">
            <h3 class="text-xl text-cyan-400 mb-3">📊 المصادر المستخدمة</h3>
            <ul class="space-y-2 text-gray-300">
                <li>🌍 ip-api.com - معلومات جغرافية دقيقة</li>
                <li>🗺️ Google Maps / OpenStreetMap - خرائط تفاعلية</li>
                <li>📧 Hunter.io - البحث عن الإيميلات (يتطلب مفتاح)</li>
            </ul>
        </div>

        <div class="border-t border-gray-700 pt-6">
            <h3 class="text-xl text-cyan-400 mb-3">🛠️ الميزات</h3>
            <ul class="grid grid-cols-2 gap-2 text-gray-300">
                <li>✅ معلومات جغرافية فورية</li>
                <li>✅ فحص المنافذ المفتوحة</li>
                <li>✅ مقياس التهديدات (Threat Meter)</li>
                <li>✅ سجل البحث والحذف</li>
                <li>✅ خريطة Maltego Graph</li>
                <li>✅ فتح الخريطة في Google Maps</li>
                <li>✅ وضع الليل والنهار</li>
                <li>✅ تصدير التقرير PDF/JSON</li>
            </ul>
        </div>

        <div class="border-t border-gray-700 pt-6 text-center text-gray-500 text-sm">
            <p>© <?php echo date('Y'); ?> OSINT Infrastructure Mapper</p>
            <p>جميع البيانات من مصادر حقيقية ومفتوحة</p>
        </div>
    </div>

</div>
</body>
</html>