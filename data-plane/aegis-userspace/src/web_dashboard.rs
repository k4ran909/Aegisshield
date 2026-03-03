//! Built-in web dashboard — serves a live stats page on port 9090.
//! Uses only std::net (zero external deps). Auto-refreshes every second.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Shared stats data between the main loop and the web server.
pub type SharedStats = Arc<Mutex<Vec<(String, u64)>>>;

/// Start the web dashboard server in a background thread.
pub fn start_web_server(listen_addr: &str, stats: SharedStats) {
    let addr = listen_addr.to_string();
    thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[web] Failed to bind {}: {}", addr, e);
                return;
            }
        };
        eprintln!("[web] Dashboard live at http://{}", addr);

        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let stats = stats.clone();
                thread::spawn(move || handle_connection(stream, &stats));
            }
        }
    });
}

fn handle_connection(mut stream: TcpStream, stats: &SharedStats) {
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let request = String::from_utf8_lossy(&buf[..n]);

    let (status, content_type, body) = if request.starts_with("GET /api/stats") {
        let json = build_stats_json(stats);
        ("200 OK", "application/json", json)
    } else if request.starts_with("GET / ") || request.starts_with("GET / HTTP") {
        (
            "200 OK",
            "text/html; charset=utf-8",
            DASHBOARD_HTML.to_string(),
        )
    } else {
        ("404 Not Found", "text/plain", "Not Found".to_string())
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn build_stats_json(stats: &SharedStats) -> String {
    let data = stats.lock().unwrap();
    let mut parts = Vec::new();
    for (name, value) in data.iter() {
        parts.push(format!("\"{}\":{}", name, value));
    }
    format!("{{{}}}", parts.join(","))
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AegisShield — Live Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0e1a;--card:#111827;--border:#1e293b;--accent:#22d3ee;--green:#10b981;
--red:#ef4444;--orange:#f59e0b;--purple:#a78bfa;--text:#e2e8f0;--dim:#64748b}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;overflow-x:hidden}
.header{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%);
border-bottom:1px solid var(--border);padding:20px 32px;display:flex;align-items:center;gap:16px}
.logo{font-size:28px;font-weight:700;background:linear-gradient(135deg,var(--accent),var(--purple));
-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.status{display:flex;align-items:center;gap:8px;margin-left:auto;font-size:13px;color:var(--dim)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;padding:24px 32px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;
transition:transform .2s,box-shadow .2s}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,.3)}
.card-label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);margin-bottom:8px}
.card-value{font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace}
.card-rate{font-size:13px;color:var(--dim);margin-top:4px;font-family:'JetBrains Mono',monospace}
.rx .card-value{color:var(--accent)}
.pass .card-value{color:var(--green)}
.drop .card-value{color:var(--red)}
.block .card-value{color:var(--orange)}
.conn .card-value{color:var(--purple)}
.section-title{padding:24px 32px 8px;font-size:14px;text-transform:uppercase;letter-spacing:2px;color:var(--dim)}
.bar-row{display:flex;align-items:center;gap:12px;padding:6px 32px}
.bar-label{width:160px;font-size:13px;color:var(--dim);font-family:'JetBrains Mono',monospace}
.bar-track{flex:1;height:24px;background:#1e293b;border-radius:6px;overflow:hidden;position:relative}
.bar-fill{height:100%;border-radius:6px;transition:width .5s ease;min-width:2px}
.bar-val{position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:12px;
font-family:'JetBrains Mono',monospace;color:#fff;text-shadow:0 1px 4px rgba(0,0,0,.5)}
.footer{text-align:center;padding:24px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);margin-top:24px}
</style>
</head>
<body>
<div class="header">
  <div class="logo">🛡️ AegisShield</div>
  <span style="color:var(--dim);font-size:14px">TC/eBPF DDoS Protection</span>
  <div class="status"><div class="dot"></div><span id="uptime">Connecting...</span></div>
</div>

<div class="grid" id="top-cards"></div>

<div class="section-title">Attack Mitigation Breakdown</div>
<div id="bars"></div>

<div class="footer">AegisShield v0.3.0 — eBPF/TC packet filtering at wire speed | Auto-refresh: 1s</div>

<script>
const CARDS=[
  {key:'rx_packets',label:'Total RX',cls:'rx'},
  {key:'passed_total',label:'Passed',cls:'pass'},
  {key:'dropped_total',label:'Dropped',cls:'drop'},
  {key:'blocklist_drops',label:'Blacklisted',cls:'block'},
  {key:'conntrack_bypass',label:'Conntrack Fast',cls:'conn'},
];
const BARS=[
  {key:'udp_rate_drops',label:'UDP Flood',color:'#ef4444'},
  {key:'syn_flood_drops',label:'SYN Flood',color:'#f59e0b'},
  {key:'icmp_rate_drops',label:'ICMP Flood',color:'#f97316'},
  {key:'dns_amp_drops',label:'DNS Amplification',color:'#8b5cf6'},
  {key:'gre_flood_drops',label:'GRE Tunnel',color:'#ec4899'},
  {key:'fragment_drops',label:'Fragment Attack',color:'#06b6d4'},
  {key:'acl_drops',label:'ACL Blocked',color:'#64748b'},
  {key:'blocklist_drops',label:'Blocklist Hits',color:'#dc2626'},
];
let prev={},startTime=Date.now();
function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';
if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function fmtTime(ms){let s=Math.floor(ms/1000),m=Math.floor(s/60),h=Math.floor(m/60);
s%=60;m%=60;return(h>0?h+'h ':'')+(m>0?m+'m ':'')+s+'s'}

async function update(){
  try{
    const r=await fetch('/api/stats');
    const d=await r.json();
    // Top cards
    let html='';
    CARDS.forEach(c=>{
      const v=d[c.key]||0;const p=prev[c.key]||v;
      const rate=v-p;
      html+=`<div class="card ${c.cls}"><div class="card-label">${c.label}</div>
        <div class="card-value">${fmt(v)}</div>
        <div class="card-rate">${rate>=0?'+':''}${fmt(rate)}/s</div></div>`;
    });
    document.getElementById('top-cards').innerHTML=html;
    // Bars
    const totalDrop=d.dropped_total||1;
    let bhtml='';
    BARS.forEach(b=>{
      const v=d[b.key]||0;const pct=Math.min((v/Math.max(totalDrop,1))*100,100);
      bhtml+=`<div class="bar-row"><div class="bar-label">${b.label}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${b.color}"></div>
        <div class="bar-val">${fmt(v)}</div></div></div>`;
    });
    document.getElementById('bars').innerHTML=bhtml;
    document.getElementById('uptime').textContent='Active · '+fmtTime(Date.now()-startTime);
    prev=d;
  }catch(e){document.getElementById('uptime').textContent='Reconnecting...';}
}
setInterval(update,1000);update();
</script>
</body>
</html>
"##;
