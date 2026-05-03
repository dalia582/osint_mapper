<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm'])) {
    $files = ['history.json', 'stats.json'];
    $cleared = [];
    foreach ($files as $f) {
        if (file_exists($f)) {
            file_put_contents($f, '[]');
            $cleared[] = $f;
        }
    }
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Clear Data — OSINT Mapper</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
body{background:#050a14;color:#e2e8f0;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.box{background:#0d1f3c;border:1px solid #1a3a5c;border-radius:16px;padding:32px;max-width:400px;text-align:center;}
h2{color:#ef4444;margin-bottom:12px;font-size:20px;}
p{color:#64748b;font-size:13px;margin-bottom:24px;line-height:1.6;}
.btn-confirm{padding:12px 24px;background:#ef4444;border:none;border-radius:10px;color:#fff;font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;margin-right:8px;}
.btn-cancel{padding:12px 24px;background:rgba(100,116,139,.2);border:1px solid #1a3a5c;border-radius:10px;color:#94a3b8;font-family:'JetBrains Mono',monospace;font-size:13px;cursor:pointer;text-decoration:none;display:inline-block;}
</style>
</head>
<body>
<div class="box">
  <h2>⚠️ Effacer les données</h2>
  <p>Cette action va effacer l'historique des investigations et les statistiques. Cette action est irréversible.</p>
  <form method="POST">
    <button class="btn-confirm" type="submit" name="confirm" value="1">🗑 Confirmer</button>
    <a class="btn-cancel" href="index.php">Annuler</a>
  </form>
</div>
</body>
</html>
