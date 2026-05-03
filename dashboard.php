<?php
$historyFile = '../history.json';
if (!file_exists($historyFile)) $historyFile = 'history.json';
$history = file_exists($historyFile) ? json_decode(file_get_contents($historyFile), true) ?? [] : [];

$total = count($history);
$critical = count(array_filter($history, fn($h)=>($h['threat_level']??'')==='CRITICAL'));
$high     = count(array_filter($history, fn($h)=>($h['threat_level']??'')==='HIGH'));
$countries = array_count_values(array_column($history,'country'));
arsort($countries);
$avgScore = $total ? round(array_sum(array_column($history,'threat_score'))/$total) : 0;
?>
<!DOCTYPE html>
<html dir="ltr" lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — OSINT Mapper</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg:#050a14;--card:#0d1f3c;--border:#1a3a5c;--accent:#00d4ff;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--muted:#64748b;--text:#e2e8f0;--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;padding:24px 20px;background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(0,212,255,.06) 0%,transparent 60%);}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;}
.wrap{max-width:1280px;margin:0 auto;position:relative;z-index:1;}
.top-bar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;padding:16px 24px;background:rgba(10,22,40,.8);backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:14px;}
h1{font-size:22px;font-weight:800;background:linear-gradient(90deg,var(--accent),#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.back-btn{display:flex;align-items:center;gap:6px;padding:8px 16px;border-radius:10px;background:rgba(0,212,255,.1);border:1px solid var(--accent);color:var(--accent);font-family:var(--mono);font-size:12px;text-decoration:none;transition:all .2s;}
.back-btn:hover{background:var(--accent);color:var(--bg);}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}
@media(max-width:900px){.grid-4{grid-template-columns:1fr 1fr;}.grid-2{grid-template-columns:1fr;}}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;text-align:center;transition:border-color .2s;}
.stat-card:hover{border-color:var(--accent);}
.stat-icon{font-size:28px;margin-bottom:10px;}
.stat-val{font-size:38px;font-weight:800;font-family:var(--mono);}
.stat-label{color:var(--muted);font-family:var(--mono);font-size:12px;margin-top:4px;}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:22px;margin-bottom:20px;}
.card-title{font-size:15px;font-weight:700;margin-bottom:18px;display:flex;align-items:center;gap:8px;}
canvas{max-height:280px;}
.hist-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:var(--mono);font-size:12px;}
.hist-row:last-child{border-bottom:none;}
.badge{padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;}
.b-red{background:rgba(239,68,68,.2);color:var(--red);}
.b-orange{background:rgba(249,115,22,.2);color:#f97316;}
.b-yellow{background:rgba(245,158,11,.2);color:var(--yellow);}
.b-green{background:rgba(16,185,129,.2);color:var(--green);}
</style>
</head>
<body>
<div class="wrap">
<div class="top-bar">
  <h1>📊 Threat Intelligence Dashboard</h1>
  <a class="back-btn" href="index.php"><i class="fas fa-arrow-left"></i> Retour</a>
</div>

<div class="grid-4">
  <div class="stat-card">
    <div class="stat-icon">🔍</div>
    <div class="stat-val" style="color:var(--accent)"><?=$total?></div>
    <div class="stat-label">IPs Analysées</div>
  </div>
  <div class="stat-card">
    <div class="stat-icon">🔴</div>
    <div class="stat-val" style="color:var(--red)"><?=$critical?></div>
    <div class="stat-label">Niveau CRITICAL</div>
  </div>
  <div class="stat-card">
    <div class="stat-icon">🌍</div>
    <div class="stat-val" style="color:var(--green)"><?=count($countries)?></div>
    <div class="stat-label">Pays Différents</div>
  </div>
  <div class="stat-card">
    <div class="stat-icon">📈</div>
    <div class="stat-val" style="color:var(--yellow)"><?=$avgScore?>%</div>
    <div class="stat-label">Score Moyen</div>
  </div>
</div>

<div class="grid-2">
  <div class="card">
    <div class="card-title">🌍 Distribution par Pays</div>
    <canvas id="countryChart"></canvas>
  </div>
  <div class="card">
    <div class="card-title">⚠️ Niveaux de Menace</div>
    <canvas id="threatChart"></canvas>
  </div>
</div>

<div class="card">
  <div class="card-title">📋 Historique des Investigations</div>
  <?php if(empty($history)): ?>
  <p style="color:var(--muted);font-family:var(--mono);font-size:13px">Aucune investigation enregistrée.</p>
  <?php else: foreach(array_slice($history,0,15) as $h):
    $lvl = $h['threat_level']??'LOW';
    $bc  = $lvl==='CRITICAL'?'b-red':($lvl==='HIGH'?'b-orange':($lvl==='MEDIUM'?'b-yellow':'b-green'));
  ?>
  <div class="hist-row">
    <span style="color:var(--accent);min-width:120px"><?=htmlspecialchars($h['ip'])?></span>
    <span style="color:var(--muted)"><?=htmlspecialchars($h['country']??'?')?></span>
    <span class="badge <?=$bc?>"><?=$lvl?> — <?=$h['threat_score']??0?>%</span>
    <span style="color:var(--muted)"><?=$h['last_seen']?></span>
    <a href="index.php?ip=<?=urlencode($h['ip'])?>" style="color:var(--accent);text-decoration:none;padding:4px 10px;border-radius:6px;background:rgba(0,212,255,.1);border:1px solid var(--accent)">🔍 Analyser</a>
  </div>
  <?php endforeach; endif;?>
</div>
</div>

<script>
const countries = <?=json_encode(array_slice($countries,0,6,true))?>;
const history   = <?=json_encode($history)?>;

new Chart(document.getElementById('countryChart'), {
  type: 'pie',
  data: {
    labels: Object.keys(countries),
    datasets: [{ data: Object.values(countries),
      backgroundColor: ['#00d4ff','#10b981','#f59e0b','#ef4444','#7c3aed','#f97316'],
      borderColor: '#0a1628', borderWidth: 2 }]
  },
  options: { plugins: { legend: { labels: { color:'#94a3b8', font:{family:'JetBrains Mono',size:11} } } } }
});

const lvls = ['CRITICAL','HIGH','MEDIUM','LOW'];
const lvlCounts = lvls.map(l => history.filter(h=>h.threat_level===l).length);
new Chart(document.getElementById('threatChart'), {
  type: 'doughnut',
  data: {
    labels: lvls,
    datasets: [{ data: lvlCounts,
      backgroundColor: ['#ef4444','#f97316','#f59e0b','#10b981'],
      borderColor: '#0a1628', borderWidth: 2 }]
  },
  options: { plugins: { legend: { labels: { color:'#94a3b8', font:{family:'JetBrains Mono',size:11} } } } }
});
</script>
</body>
</html>
