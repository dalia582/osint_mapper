<?php ?>
<!DOCTYPE html>
<html dir="ltr" lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>About — OSINT Mapper</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--bg:#050a14;--card:#0d1f3c;--border:#1a3a5c;--accent:#00d4ff;--accent2:#7c3aed;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--muted:#64748b;--text:#e2e8f0;--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);padding:24px 20px;min-height:100vh;background-image:radial-gradient(ellipse 80% 50% at 50% -20%,rgba(0,212,255,.06) 0%,transparent 60%);}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;}
.wrap{max-width:1100px;margin:0 auto;position:relative;z-index:1;}
.top-bar{display:flex;align-items:center;justify-content:space-between;padding:16px 24px;background:rgba(10,22,40,.9);border:1px solid var(--border);border-radius:14px;margin-bottom:28px;}
h1{font-size:22px;font-weight:800;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.back-btn{display:flex;align-items:center;gap:6px;padding:8px 16px;border-radius:10px;background:rgba(0,212,255,.1);border:1px solid var(--accent);color:var(--accent);font-family:var(--mono);font-size:12px;text-decoration:none;transition:all .2s;}
.back-btn:hover{background:var(--accent);color:var(--bg);}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:20px;}
.card:hover{border-color:rgba(0,212,255,.3);}
.section-title{font-size:20px;font-weight:800;margin-bottom:18px;display:flex;align-items:center;gap:10px;}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
@media(max-width:700px){.grid-2{grid-template-columns:1fr;}}
.tool-card{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:18px;transition:all .3s;}
.tool-card:hover{border-color:var(--accent);transform:translateY(-3px);}
.tool-icon{font-size:32px;margin-bottom:10px;}
.tool-name{font-size:16px;font-weight:700;margin-bottom:6px;}
.tool-desc{color:var(--muted);font-family:var(--mono);font-size:12px;line-height:1.6;}
.pipeline-row{display:flex;align-items:center;gap:0;margin-bottom:8px;}
.step{flex:1;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:0;text-align:center;font-family:var(--mono);font-size:12px;}
.step:first-child{border-radius:10px 0 0 10px;}
.step:last-child{border-radius:0 10px 10px 0;}
.step.active{border-color:var(--accent);background:rgba(0,212,255,.06);color:var(--accent);}
.arrow-icon{color:var(--muted);font-size:16px;padding:0 4px;}
.api-row{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:var(--mono);font-size:12px;}
.api-row:last-child{border-bottom:none;}
.api-name{color:var(--accent);font-weight:700;}
.api-desc{color:var(--muted);}
.badge{padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;}
.b-green{background:rgba(16,185,129,.2);color:var(--green);}
.b-yellow{background:rgba(245,158,11,.2);color:var(--yellow);}
.feature-list{list-style:none;}
.feature-list li{padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:var(--mono);font-size:12px;color:var(--muted);display:flex;align-items:center;gap:8px;}
.feature-list li:last-child{border-bottom:none;}
.feature-list li span{color:var(--accent);}
</style>
</head>
<body>
<div class="wrap">

<div class="top-bar">
  <h1>🕵️ OSINT Infrastructure Mapper — Documentation</h1>
  <a class="back-btn" href="index.php"><i class="fas fa-arrow-left"></i> Retour</a>
</div>

<!-- OBJECTIF -->
<div class="card">
  <div class="section-title">🎯 Objectif du Projet</div>
  <p style="color:var(--muted);font-family:var(--mono);font-size:13px;line-height:1.8;margin-bottom:16px">
    Ce projet simule une investigation OSINT complète visant à <strong style="color:var(--text)">reconstruire l'infrastructure d'un attaquant</strong>
    à partir de sources ouvertes. En partant d'une simple adresse IP suspecte, l'outil remonte jusqu'aux domaines associés,
    aux emails, et tente d'attribuer l'activité à un groupe de menace connu.
  </p>
  <div class="pipeline-row">
    <?php $steps=[['🎯','IP Suspecte'],['🔍','Enrichissement'],['🌐','Domaines'],['✉️','Emails'],['🎭','Attribution']];
    foreach($steps as $i=>$s):?>
    <?php if($i>0) echo '<span class="arrow-icon">→</span>'; ?>
    <div class="step <?=$i===0||$i===4?'active':''?>">
      <div><?=$s[0]?></div>
      <div style="margin-top:4px"><?=$s[1]?></div>
    </div>
    <?php endforeach;?>
  </div>
</div>

<!-- OUTILS -->
<div class="card">
  <div class="section-title">🛠️ Outils de Référence</div>
  <div class="grid-2">
    <div class="tool-card">
      <div class="tool-icon">🕸️</div>
      <div class="tool-name">Maltego</div>
      <div class="tool-desc">Plateforme de visualisation des relations entre entités : IPs, domaines, emails, personnes. Utilisé pour cartographier l'infrastructure d'un attaquant. Reproduit ici via le graphe Canvas interactif.</div>
    </div>
    <div class="tool-card">
      <div class="tool-icon">🔭</div>
      <div class="tool-name">Shodan</div>
      <div class="tool-desc">Moteur de recherche pour appareils connectés. Indexe les bannières de services, ports ouverts, OS, certificats SSL et vulnérabilités CVE. Simulé ici avec des données représentatives.</div>
    </div>
    <div class="tool-card">
      <div class="tool-icon">🦠</div>
      <div class="tool-name">VirusTotal</div>
      <div class="tool-desc">Agrégateur de 70+ moteurs antivirus et de réputation. Permet d'analyser IPs, domaines, URLs et fichiers. Retourne un score de réputation et les détections par moteur.</div>
    </div>
    <div class="tool-card">
      <div class="tool-icon">🕷️</div>
      <div class="tool-name">SpiderFoot</div>
      <div class="tool-desc">Framework OSINT open-source automatisant la collecte multi-sources. Interroge 200+ sources (WHOIS, DNS, réseaux sociaux, dark web). Le pipeline de ce projet suit sa méthodologie.</div>
    </div>
  </div>
</div>

<!-- APIs -->
<div class="card">
  <div class="section-title">🔌 APIs Intégrées</div>
  <div class="api-row">
    <span class="api-name">ip-api.com</span>
    <span class="api-desc">Géolocalisation, ISP, ASN, détection proxy/hosting</span>
    <span class="badge b-green">✅ Réel</span>
  </div>
  <div class="api-row">
    <span class="api-name">VirusTotal API v3</span>
    <span class="api-desc">Réputation IP, détections, score communautaire</span>
    <span class="badge b-yellow">⚗️ Demo</span>
  </div>
  <div class="api-row">
    <span class="api-name">AbuseIPDB API</span>
    <span class="api-desc">Score d'abus, rapports d'incidents, catégories d'attaques</span>
    <span class="badge b-yellow">⚗️ Demo</span>
  </div>
  <div class="api-row">
    <span class="api-name">Shodan API</span>
    <span class="api-desc">Ports, bannières, OS, CVEs détectées</span>
    <span class="badge b-yellow">⚗️ Demo</span>
  </div>
  <div class="api-row">
    <span class="api-name">Hunter.io API</span>
    <span class="api-desc">Découverte d'emails associés à un domaine</span>
    <span class="badge b-yellow">⚗️ Demo</span>
  </div>
  <div class="api-row">
    <span class="api-name">PHP fsockopen()</span>
    <span class="api-desc">Scan des ports TCP ouverts (16 ports)</span>
    <span class="badge b-green">✅ Réel</span>
  </div>
  <div class="api-row">
    <span class="api-name">PHP gethostbyaddr()</span>
    <span class="api-desc">Résolution PTR / Reverse DNS</span>
    <span class="badge b-green">✅ Réel</span>
  </div>
</div>

<!-- FONCTIONNALITES -->
<div class="card">
  <div class="section-title">✨ Fonctionnalités</div>
  <div class="grid-2">
    <ul class="feature-list">
      <li><span>✅</span> Investigation complète IP → Attribution</li>
      <li><span>✅</span> Géolocalisation réelle (ip-api.com)</li>
      <li><span>✅</span> Scan de 16 ports TCP</li>
      <li><span>✅</span> Reverse DNS / PTR Record</li>
      <li><span>✅</span> Analyse VirusTotal (70+ moteurs)</li>
      <li><span>✅</span> Score AbuseIPDB</li>
      <li><span>✅</span> Renseignement Shodan (OS, bannières, CVEs)</li>
    </ul>
    <ul class="feature-list">
      <li><span>✅</span> Découverte de domaines associés</li>
      <li><span>✅</span> Découverte d'emails (Hunter.io)</li>
      <li><span>✅</span> Attribution — Threat Actor Groups</li>
      <li><span>✅</span> Graphe Maltego interactif (Canvas)</li>
      <li><span>✅</span> Export JSON &amp; PDF</li>
      <li><span>✅</span> Dashboard statistiques (Chart.js)</li>
      <li><span>✅</span> Comparaison de 2 IPs côte à côte</li>
    </ul>
  </div>
</div>

<div style="text-align:center;padding:20px;color:var(--muted);font-family:var(--mono);font-size:11px">
  OSINT Infrastructure Mapper v7 · Sécurité Informatique · <?=date('Y')?>
</div>
</div>
</body>
</html>
