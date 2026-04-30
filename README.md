# 🔍 OSINT Infrastructure Mapper

## 📝 تقرير المشروع

### الهدف
بناء منصة متكاملة لتحليل عناوين IP باستخدام OSINT.

### الميزات
- ✅ معلومات جغرافية حقيقية
- ✅ فحص المنافذ المفتوحة
- ✅ حساب نسبة الخطورة
- ✅ رسم Maltego Graph
- ✅ سجل بحث وإحصائيات
- ✅ خرائط Google Maps
- ✅ تصدير PDF و JSON

### التقنيات المستخدمة
| التقنية | الاستخدام |
|----------|-----------|
| PHP | Backend |
| HTML/CSS | واجهة المستخدم |
| JavaScript | تفاعل وجلب البيانات |
| Leaflet.js | خرائط تفاعلية |
| Chart.js | رسوم بيانية |
| html2pdf | تصدير PDF |

### APIs المستخدمة
- ip-api.com (جغرافيا + ISP)
- VirusTotal (سمعة IP)
- AbuseIPDB (تقارير الإساءة)

### طريقة التشغيل
`bash
php -S localhost:8000

