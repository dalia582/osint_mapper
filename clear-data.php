<?php
// clear-data.php - مسح البيانات المؤقتة

if (isset($_GET['confirm']) && $_GET['confirm'] == 'yes') {
    if (file_exists('history.json')) unlink('history.json');
    if (file_exists('stats.json')) unlink('stats.json');
    
    // مسح ملفات الكاش
    array_map('unlink', glob('cache_*.json'));
    
    $message = "✅ تم مسح جميع البيانات بنجاح";
}
?>
<!DOCTYPE html>
<html dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>مسح البيانات - OSINT</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white p-6">
<div class="container mx-auto max-w-md">

    <div class="bg-gray-800 p-8 rounded-xl text-center">
        <span class="text-6xl">🗑️</span>
        <h1 class="text-2xl text-cyan-400 mt-3">مسح البيانات</h1>
        
        <?php if (isset($message)): ?>
            <div class="bg-green-600 p-4 rounded-xl mt-6"><?php echo $message; ?></div>
            <a href="index.php" class="block mt-6 bg-cyan-600 px-6 py-3 rounded-xl hover:bg-cyan-500">🏠 العودة للرئيسية</a>
        <?php else: ?>
            <p class="text-gray-400 mt-4">هل أنت متأكدة من مسح كل البيانات؟</p>
            <p class="text-sm text-gray-500 mt-2">(سجل البحث + الإحصائيات)</p>
            <div class="flex gap-4 mt-6">
                <a href="?confirm=yes" class="flex-1 bg-red-600 px-4 py-2 rounded-xl hover:bg-red-500">نعم، امسحي</a>
                <a href="index.php" class="flex-1 bg-gray-700 px-4 py-2 rounded-xl hover:bg-gray-600">لا، عودي</a>
            </div>
        <?php endif; ?>
    </div>

</div>
</body>
</html>