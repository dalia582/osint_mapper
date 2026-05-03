<?php
function getIPInfo($ip){
    $geo=@file_get_contents("http://ip-api.com/json/{$ip}?fields=66846719");
    if(!$geo)return[];
    $d=json_decode($geo,true);
    if(($d['status']??'')!=='success')return[];
    return['country'=>$d['country']??'?','city'=>$d['city']??'?','isp'=>$d['isp']??'?',
           'as'=>$d['as']??'?','lat'=>$d['lat']??0,'lon'=>$d['lon']??0,
           'hosting'=>$d['hosting']??false,'proxy'=>$d['proxy']??false,'countryCode'=>$d['countryCode']??'xx'];
}
function getPorts($ip){
    $pm=[21=>'FTP',22=>'SSH',23=>'Telnet',80=>'HTTP',443=>'HTTPS',3306=>'MySQL',3389=>'RDP',8080=>'Alt-HTTP'];
    $open=[];
    foreach($pm as $p=>$s){$c=@fsockopen($ip,$p,$e,$es,0.3);if($c){$open[$p]=$s;fclose($c);}}
    return $open;
}
function mockVT($ip){srand(crc32($ip));$m=rand(0,12);return['malicious'=>$m,'suspicious'=>rand(0,6),'reputation'=>$m>5?'Malicious':($m>0?'Suspicious':'Clean')];}
function mockAbuse($ip){srand(crc32($ip.'a'));return['abuse_score'=>rand(0,100),'total_reports'=>rand(0,400)];}
function threatScore($d,$p,$vt,$ab){
    $s=0;if($d['hosting']??false)$s+=30;if($d['proxy']??false)$s+=25;
    $s+=count($p)*3;$s+=min($vt['malicious']*4,40);$s+=min((int)($ab['abuse_score']/5),20);
    return min($s,100);
}

$ip1=trim($_GET['ip1']??'');$ip2=trim($_GET['ip2']??'');
$d1=[];$d2=[];$p1=[];$p2=[];$vt1=[];$vt2=[];$ab1=[];$ab2=[];$s1=0;$s2=0;
$valid=fn($ip)=>filter_var($ip,FILTER_VALIDATE_IP)&&filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE);
if($ip1&&$ip2&&$valid($ip1)&&$valid($ip2)){
    $d1=getIPInfo($ip1);$d2=getIPInfo($ip2);
    $p1=getPorts($ip1);$p2=getPorts($ip2);
    $vt1=mockVT($ip1);$vt2=mockVT($ip2);
    $ab1=mockAbuse($ip1);$ab2=mockAbuse($ip2);
    $s1=threatScore($d1,$p1,$vt1,$ab1);$s2=threatScore($d2,$p2,$vt2,$ab2);
}
?>
<!DOCTYPE html>
<html dir="ltr" lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compare — OSINT Mapper</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
:root{--bg:#050a14;--card:#0d1f3c;--border:#1a3a5c;--accent:#00d4ff;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--muted:#64748b;--text:#e2e8f0;--mono:'JetBrains Mono',monospace;--sans:'Syne',sans-serif;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);padding:24px 20px;min-height:100vh;}
.wrap{max-width:1200px;margin:0 auto;}
.top-bar{display:flex;align-items:center;justify-content:space-between;padding:16px 24px;background:rgba(10,22,40,.9);border:1px solid var(--border);border-radius:14px;margin-bottom:24px;}
h1{font-size:20px;font-weight:800;background:linear-gradient(90deg,var(--accent),#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
.back-btn{display:flex;align-items:center;gap:6px;padding:8px 16px;border-radius:10px;background:rgba(0,212,255,.1);border:1px solid var(--accent);color:var(--accent);font-family:var(--mono);font-size:12px;text-decoration:none;}
.search-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:22px;margin-bottom:24px;}
.search-row{display:flex;gap:12px;align-items:center;}
.ip-input{flex:1;padding:12px 16px;background:#050a14;border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:var(--mono);font-size:14px;outline:none;}
.ip-input:focus{border-color:var(--accent);}
.vs{font-size:18px;font-weight:800;color:var(--muted);flex-shrink:0;}
.btn{padding:12px 24px;background:var(--accent);border:none;border-radius:10px;color:#050a14;font-family:var(--mono);font-weight:700;font-size:13px;cursor:pointer;}
.compare-grid{display:grid;grid-template-columns:1fr 60px 1fr;gap:0;margin-bottom:24px;}
.col-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;}
.col-left{border-radius:14px 0 0 14px;border-right:none;}
.col-right{border-radius:0 14px 14px 0;border-left:none;}
.col-mid{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;background:rgba(26,58,92,.3);border-top:1px solid var(--border);border-bottom:1px solid var(--border);}
.col-title{font-size:14px;font-weight:700;font-family:var(--mono);color:var(--accent);margin-bottom:14px;text-align:center;}
.row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);font-family:var(--mono);font-size:12px;}
.row:last-child{border-bottom:none;}
.lbl{color:var(--muted);}
.val{color:var(--text);font-weight:600;}
.mid-lbl{font-family:var(--mono);font-size:9px;color:var(--muted);text-align:center;padding:4px 6px;background:var(--card);border-radius:6px;width:50px;}
.score-big{text-align:center;font-size:42px;font-weight:800;font-family:var(--mono);margin:10px 0;}
.bar-wrap{height:8px;background:#050a14;border-radius:4px;overflow:hidden;margin:6px 0;}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--green),var(--yellow),var(--red));border-radius:4px;}
.winner-badge{text-align:center;padding:8px;border-radius:10px;font-family:var(--mono);font-size:11px;font-weight:700;margin-top:10px;}
.port-tag{display:inline-block;margin:2px;padding:4px 8px;border-radius:6px;font-family:var(--mono);font-size:11px;background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.3);color:#a78bfa;}
@media(max-width:700px){.compare-grid{grid-template-columns:1fr;}.col-left,.col-right,.col-mid{border-radius:14px!important;border:1px solid var(--border)!important;}.col-mid{flex-direction:row;flex-wrap:wrap;justify-content:center;}}
</style>
</head>
<body>
<div class="wrap">
<div class="top-bar">
  <h1>⚖️ Comparaison d'IPs</h1>
  <a class="back-btn" href="index.php"><i class="fas fa-arrow-left"></i> Retour</a>
</div>

<div class="search-card">
  <form method="GET" class="search-row">
    <input class="ip-input" type="text" name="ip1" placeholder="IP #1  (ex: 8.8.8.8)" value="<?=htmlspecialchars($ip1)?>">
    <span class="vs">VS</span>
    <input class="ip-input" type="text" name="ip2" placeholder="IP #2  (ex: 1.1.1.1)" value="<?=htmlspecialchars($ip2)?>">
    <button class="btn" type="submit"><i class="fas fa-balance-scale"></i> Comparer</button>
  </form>
</div>

<?php if($d1&&$d2): ?>
<div class="compare-grid">
  <!-- LEFT -->
  <div class="col-card col-left">
    <div class="col-title" style="color:var(--accent)">🔵 <?=htmlspecialchars($ip1)?></div>
    <?php
    $score1color=$s1>=70?'var(--red)':($s1>=45?'#f97316':($s1>=20?'var(--yellow)':'var(--green))'));
    ?>
    <div class="score-big" style="color:<?=$score1color?>"><?=$s1?>%</div>
    <div class="bar-wrap"><div class="bar-fill" style="width:<?=$s1?>%"></div></div>
    <?php $lvl1=$s1>=70?'CRITICAL':($s1>=45?'HIGH':($s1>=20?'MEDIUM':'LOW'));?>
    <div class="winner-badge" style="background:<?=$score1color?>22;color:<?=$score1color?>;border:1px solid <?=$score1color?>44"><?=$lvl1?></div>
    <br>
    <?php $r=[['Country',$d1['country']],['City',$d1['city']],['ISP',substr($d1['isp'],0,25)],['ASN',$d1['as']],
               ['Hosting',$d1['hosting']?'⚠️ Yes':'✅ No'],['Proxy',$d1['proxy']?'⚠️ Yes':'✅ No'],
               ['VT Malicious',$vt1['malicious'].' engines'],['Abuse Score',$ab1['abuse_score'].'%'],['Open Ports',count($p1)]];
    foreach($r as $row):?>
    <div class="row"><span class="lbl"><?=$row[0]?></span><span class="val"><?=htmlspecialchars((string)$row[1])?></span></div>
    <?php endforeach;?>
    <div style="margin-top:12px">
      <?php foreach($p1 as $port=>$svc): ?>
      <span class="port-tag"><?=$port?>/<?=$svc?></span>
      <?php endforeach;?>
    </div>
  </div>

  <!-- MID -->
  <div class="col-mid">
    <span class="mid-lbl">Country</span>
    <span class="mid-lbl">City</span>
    <span class="mid-lbl">ISP</span>
    <span class="mid-lbl">Hosting</span>
    <span class="mid-lbl">Proxy</span>
    <span class="mid-lbl">VT</span>
    <span class="mid-lbl">Abuse</span>
    <span class="mid-lbl">Ports</span>
  </div>

  <!-- RIGHT -->
  <div class="col-card col-right">
    <div class="col-title" style="color:#a78bfa">🟣 <?=htmlspecialchars($ip2)?></div>
    <?php $score2color=$s2>=70?'var(--red)':($s2>=45?'#f97316':($s2>=20?'var(--yellow)':'var(--green))'));?>
    <div class="score-big" style="color:<?=$score2color?>"><?=$s2?>%</div>
    <div class="bar-wrap"><div class="bar-fill" style="width:<?=$s2?>%"></div></div>
    <?php $lvl2=$s2>=70?'CRITICAL':($s2>=45?'HIGH':($s2>=20?'MEDIUM':'LOW'));?>
    <div class="winner-badge" style="background:<?=$score2color?>22;color:<?=$score2color?>;border:1px solid <?=$score2color?>44"><?=$lvl2?></div>
    <br>
    <?php $r=[['Country',$d2['country']],['City',$d2['city']],['ISP',substr($d2['isp'],0,25)],['ASN',$d2['as']],
               ['Hosting',$d2['hosting']?'⚠️ Yes':'✅ No'],['Proxy',$d2['proxy']?'⚠️ Yes':'✅ No'],
               ['VT Malicious',$vt2['malicious'].' engines'],['Abuse Score',$ab2['abuse_score'].'%'],['Open Ports',count($p2)]];
    foreach($r as $row):?>
    <div class="row"><span class="lbl"><?=$row[0]?></span><span class="val"><?=htmlspecialchars((string)$row[1])?></span></div>
    <?php endforeach;?>
    <div style="margin-top:12px">
      <?php foreach($p2 as $port=>$svc): ?>
      <span class="port-tag"><?=$port?>/<?=$svc?></span>
      <?php endforeach;?>
    </div>
  </div>
</div>

<!-- VERDICT -->
<div style="text-align:center;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:14px">
  <?php if($s1>$s2):?>
  <div style="font-size:18px;font-weight:800;color:var(--red)">⚠️ <?=htmlspecialchars($ip1)?> est plus dangereuse</div>
  <div style="color:var(--muted);font-family:var(--mono);font-size:12px;margin-top:6px">Différence de score: +<?=$s1-$s2?>%</div>
  <?php elseif($s2>$s1):?>
  <div style="font-size:18px;font-weight:800;color:var(--red)">⚠️ <?=htmlspecialchars($ip2)?> est plus dangereuse</div>
  <div style="color:var(--muted);font-family:var(--mono);font-size:12px;margin-top:6px">Différence de score: +<?=$s2-$s1?>%</div>
  <?php else:?>
  <div style="font-size:18px;font-weight:800;color:var(--yellow)">⚖️ Niveau de menace identique</div>
  <?php endif;?>
</div>
<?php endif;?>
</div>
</body>
</html>
