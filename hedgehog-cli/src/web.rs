// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Localhost web dashboard for Gorse.
//!
//! `gorse web` starts a tiny HTTP server on localhost serving
//! a single-page dashboard with live data from the taint engine,
//! security packs, agent hooks, and event history.

use std::io::Write;
use std::net::TcpListener;

use crate::{config, history, hook, logging};

/// Start the web dashboard server.
pub fn serve(port: u16, no_open: bool) {
    let addr = format!("127.0.0.1:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            eprintln!("Try a different port: gorse web --port 3142");
            std::process::exit(1);
        }
    };

    println!("Gorse Web Dashboard");
    println!("  http://{addr}");
    println!("  Press Ctrl+C to stop");
    println!();

    // Open browser
    if !no_open {
        open_browser(&format!("http://{addr}"));
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                if request.starts_with("GET /api/data") {
                    let data = dashboard_data();
                    let json = serde_json::to_string(&data).unwrap();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                        json.len(), json
                    );
                    let _ = stream.write_all(response.as_bytes());
                } else if request.starts_with("GET") {
                    let html = dashboard_html();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        html.len(), html
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
            Err(e) => {
                log::warn!("Connection error: {e}");
            }
        }
    }
}

pub(crate) fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
}

fn dashboard_data() -> serde_json::Value {
    // Same truth as `gorse status`: found = credential locations that
    // exist, protected = found only while a hook or the sensor is live.
    let protection = super::Protection::gather();
    let total = protection.found_count();
    let protected = protection.protected_count();
    let unprotected = total - protected;

    let engine = super::load_engine();
    let agents = hook::detect_agents();
    let activity = logging::recent_activity(30);
    let db_stats = history::query_stats();
    let recent = history::query_recent(20, None);

    let agents_list: Vec<serde_json::Value> = agents
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "detected": a.detected,
                "installed": a.installed,
            })
        })
        .collect();

    let recent_list: Vec<serde_json::Value> = recent
        .iter()
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "tool_name": e.tool_name,
                "command": e.command,
                "category": e.category,
                "message": e.message,
            })
        })
        .collect();

    let top_cats: Vec<serde_json::Value> = db_stats
        .top_categories
        .iter()
        .map(|(cat, cnt)| serde_json::json!({"category": cat, "count": cnt}))
        .collect();

    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": super::platform_name(),
        "secrets_total": total,
        "secrets_protected": protected,
        "secrets_unprotected": unprotected,
        "hooks": protection.hooks_json(),
        "sensor_running": protection.sensor_running,
        "rules_loaded": engine.rule_count(),
        "dcg_detected": super::dcg_detected(),
        "config_exists": config::config_path().exists(),
        "agents": agents_list,
        "activity": {
            "blocks": activity.blocks,
            "allows": activity.allows,
            "approvals": activity.approvals,
            "total": activity.total_events,
        },
        "top_categories": top_cats,
        "recent_events": recent_list,
    })
}

fn dashboard_html() -> String {
    let data = dashboard_data();
    let data_json = serde_json::to_string(&data).unwrap();
    DASHBOARD_TEMPLATE.replace("__HEDGEHOG_DATA__", &data_json)
}

const DASHBOARD_TEMPLATE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gorse Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0a;color:#e5e5e5;padding:2rem;max-width:960px;margin:0 auto}
h1{font-size:1.5rem;margin-bottom:0.25rem}
.sub{color:#666;font-size:0.875rem;margin-bottom:2rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.card{background:#141414;border:1px solid #262626;border-radius:8px;padding:1.25rem}
.card h2{font-size:0.8rem;color:#888;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.75rem}
.stat{font-size:2rem;font-weight:700}
.sl{color:#666;font-size:0.75rem}
.bar{height:6px;background:#262626;border-radius:3px;margin-top:0.5rem;overflow:hidden}
.bf{height:100%;border-radius:3px;transition:width .3s}
.g{color:#22c55e}.bg{background:#22c55e}
.r{color:#ef4444}.br{background:#ef4444}
.y{color:#eab308}.by{background:#eab308}
.dim{color:#666}
.ar{display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0;font-size:0.875rem}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot.g{background:#22c55e}.dot.x{background:#444}
.er{padding:0.5rem 0;border-bottom:1px solid #1a1a1a;font-size:0.8125rem}
.et{display:inline-block;padding:2px 6px;border-radius:3px;font-size:0.7rem;font-weight:600}
.et.b{background:#3f1111;color:#ef4444}
.et.a{background:#0f2f1a;color:#22c55e}
.et.bp{background:#2f2a0f;color:#eab308}
.et.s{background:#1a1a2f;color:#818cf8}
.ec{color:#999;margin-left:0.5rem}
.fw{grid-column:1/-1}
.ft{color:#555;font-size:0.75rem;text-align:center;margin-top:1rem}
a{color:#3b82f6;text-decoration:none}a:hover{text-decoration:underline}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>Gorse Dashboard</h1>
<div class="sub" id="ver"></div>
<div class="grid">
  <div class="card">
    <h2>Secrets</h2>
    <div class="stat" id="st">-</div>
    <div class="sl">detected on this machine</div>
    <div style="margin-top:0.75rem;display:flex;gap:1.5rem">
      <div><span class="g" id="sp">0</span> <span class="sl">protected</span></div>
      <div><span id="su">0</span> <span class="sl">unprotected</span></div>
    </div>
    <div class="bar"><div class="bf bg" id="sb"></div></div>
  </div>
  <div class="card">
    <h2>Security Rules</h2>
    <div class="stat" id="rc">-</div>
    <div class="sl">rules loaded across all packs</div>
    <div style="margin-top:0.75rem"><span class="dim" id="dcg"></span></div>
  </div>
  <div class="card">
    <h2>Activity (30 days)</h2>
    <div style="display:flex;gap:1.5rem;margin-bottom:0.75rem">
      <div><span class="stat r" id="ab">0</span><br><span class="sl">blocked</span></div>
      <div><span class="stat g" id="aa">0</span><br><span class="sl">allowed</span></div>
      <div><span class="stat y" id="ay">0</span><br><span class="sl">approved</span></div>
    </div>
    <div class="bar" style="margin-bottom:4px"><div class="bf br" id="bb"></div></div>
    <div class="bar"><div class="bf bg" id="ba"></div></div>
  </div>
  <div class="card">
    <h2>AI Agent Hooks</h2>
    <div id="al"></div>
  </div>
  <div class="card fw" id="cc" style="display:none">
    <h2>Top Blocked Categories</h2>
    <div id="cl"></div>
  </div>
  <div class="card fw">
    <h2>Recent Events</h2>
    <div id="el"></div>
  </div>
</div>
<div class="ft">Refresh for latest data &middot; <a href="/api/data">JSON API</a></div>
<script>
var D=__HEDGEHOG_DATA__;
document.getElementById('ver').textContent='v'+D.version+' \u00b7 '+D.platform;
document.getElementById('st').textContent=D.secrets_total;
document.getElementById('sp').textContent=D.secrets_protected;
var su=document.getElementById('su');
su.textContent=D.secrets_unprotected;
if(D.secrets_unprotected>0)su.className='r';
var pct=D.secrets_total>0?(D.secrets_protected/D.secrets_total*100):0;
document.getElementById('sb').style.width=pct+'%';
document.getElementById('rc').textContent=D.rules_loaded;
document.getElementById('dcg').textContent=D.dcg_detected?'DCG detected \u2014 destructive category deferred':'';
document.getElementById('ab').textContent=D.activity.blocks;
document.getElementById('aa').textContent=D.activity.allows;
document.getElementById('ay').textContent=D.activity.approvals;
var mx=Math.max(D.activity.blocks,D.activity.allows,1);
document.getElementById('bb').style.width=(D.activity.blocks/mx*100)+'%';
document.getElementById('ba').style.width=(D.activity.allows/mx*100)+'%';
var al=document.getElementById('al');
var det=D.agents.filter(function(a){return a.detected});
if(det.length===0){al.innerHTML='<div class="dim">No agents detected</div>'}
else{al.innerHTML=det.map(function(a){return'<div class="ar"><span class="dot '+(a.installed?'g':'x')+'"></span>'+a.name+' <span class="dim">'+(a.installed?'hooked':'not hooked')+'</span></div>'}).join('')}
if(D.top_categories&&D.top_categories.length>0){
document.getElementById('cc').style.display='';
var cl=document.getElementById('cl');
var mc=D.top_categories[0].count;
cl.innerHTML=D.top_categories.map(function(c){return'<div style="display:flex;align-items:center;gap:0.75rem;padding:0.25rem 0"><div style="width:120px;font-size:0.8125rem">'+c.category+'</div><div style="flex:1;height:6px;background:#262626;border-radius:3px;overflow:hidden"><div style="width:'+(c.count/mc*100)+'%;height:100%;background:#ef4444;border-radius:3px"></div></div><div style="font-size:0.8125rem;color:#888;width:30px;text-align:right">'+c.count+'</div></div>'}).join('')}
var el=document.getElementById('el');
if(D.recent_events.length===0){el.innerHTML='<div class="dim">No events yet. The agent guard (preview) records events here once it is turned on.</div>'}
else{el.innerHTML=D.recent_events.map(function(e){
var ts=e.timestamp.substring(0,19);
var cls=e.event_type==='block'?'b':e.event_type==='approved'?'bp':e.event_type.indexOf('shell')>=0?'s':'a';
var cmd=e.command.length>60?e.command.substring(0,57)+'...':e.command;
return'<div class="er"><span class="et '+cls+'">'+e.event_type.toUpperCase()+'</span> <span class="dim" style="font-size:0.75rem">'+ts+'</span><span class="ec">'+esc(cmd)+'</span>'+(e.category?'<span class="dim" style="margin-left:0.5rem;font-size:0.7rem">'+e.category+'</span>':'')+'</div>'
}).join('')}
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
</script>
</body>
</html>"##;
