"""logpipe 中心端:接收代理上报、按 (host,file_id,offset) 去重、SQLite 存储、Web 监控。

页面:主机清单 / 采集配置 / 传输状态 / 丢失排查 / 中心存储。
丢失排查原理:代理心跳上报每个文件的读取位点与大小,中心按收到的
[offset, offset+blen) 区间合并,比对出缺口(missing)与滞后(lag)。
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .common import DEFAULT_CONFIG

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs(
  host    TEXT NOT NULL,
  file_id TEXT NOT NULL,
  path    TEXT NOT NULL,
  offset  INTEGER NOT NULL,
  blen    INTEGER NOT NULL,
  text    TEXT NOT NULL,
  ts      REAL NOT NULL,
  PRIMARY KEY(host, file_id, offset)
);
CREATE TABLE IF NOT EXISTS hosts(
  host        TEXT PRIMARY KEY,
  first_seen  REAL,
  last_seen   REAL,
  spool_rows  INTEGER DEFAULT 0,
  spool_bytes INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS files(
  host    TEXT NOT NULL,
  file_id TEXT NOT NULL,
  path    TEXT NOT NULL,
  offset  INTEGER DEFAULT 0,
  size    INTEGER DEFAULT 0,
  done    INTEGER DEFAULT 0,
  updated REAL,
  PRIMARY KEY(host, file_id)
);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

DEFAULT_DOC = {
    "default": {k: v for k, v in DEFAULT_CONFIG.items() if k != "globs"},
    "hosts": {},   # "web-01": {"globs": [...]}, 按主机覆盖
}


class Central(object):
    def __init__(self, dbpath):
        self.db = sqlite3.connect(dbpath, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()
        self.ingest_events = deque()   # (ts, 条数) 用于计算速率
        self.dup_total = 0
        self.dbpath = dbpath

    # ---- 配置 ----
    def get_doc(self):
        with self.lock:
            row = self.db.execute("SELECT v FROM meta WHERE k='config'").fetchone()
        if row:
            return json.loads(row[0])
        return json.loads(json.dumps(DEFAULT_DOC))

    def save_doc(self, doc):
        with self.lock, self.db:
            self.db.execute("INSERT INTO meta(k,v) VALUES('config',?)"
                            " ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                            (json.dumps(doc, ensure_ascii=False),))

    def effective_config(self, host):
        doc = self.get_doc()
        eff = dict(doc.get("default") or {})
        eff.update((doc.get("hosts") or {}).get(host) or {})
        eff.setdefault("globs", [])
        return eff

    # ---- 写入 ----
    def ingest(self, host, records):
        now = time.time()
        with self.lock, self.db:
            before = self.db.total_changes
            self.db.executemany(
                "INSERT OR IGNORE INTO logs(host,file_id,path,offset,blen,text,ts)"
                " VALUES(?,?,?,?,?,?,?)",
                [(host, r["file_id"], r["path"], int(r["offset"]),
                  int(r["blen"]), r["text"], now) for r in records])
            accepted = self.db.total_changes - before
            self.db.execute(
                "INSERT INTO hosts(host,first_seen,last_seen) VALUES(?,?,?)"
                " ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen",
                (host, now, now))
            self.db.executemany(
                "INSERT OR IGNORE INTO files(host,file_id,path,updated) VALUES(?,?,?,?)",
                [(host, r["file_id"], r["path"], now) for r in records])
        dups = len(records) - accepted
        self.dup_total += dups
        self.ingest_events.append((now, accepted))
        while self.ingest_events and self.ingest_events[0][0] < now - 120:
            self.ingest_events.popleft()
        return accepted, dups

    def heartbeat(self, host, spool_rows, spool_bytes, files):
        now = time.time()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO hosts(host,first_seen,last_seen,spool_rows,spool_bytes)"
                " VALUES(?,?,?,?,?)"
                " ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen,"
                " spool_rows=excluded.spool_rows, spool_bytes=excluded.spool_bytes",
                (host, now, now, spool_rows, spool_bytes))
            self.db.executemany(
                "INSERT INTO files(host,file_id,path,offset,size,done,updated)"
                " VALUES(?,?,?,?,?,?,?)"
                " ON CONFLICT(host,file_id) DO UPDATE SET path=excluded.path,"
                " offset=excluded.offset, size=excluded.size,"
                " done=excluded.done, updated=excluded.updated",
                [(host, f["file_id"], f["path"], int(f["offset"]),
                  int(f["size"]), int(f["done"]), now) for f in files])

    # ---- 查询 ----
    def hosts(self):
        now = time.time()
        with self.lock:
            hrows = self.db.execute(
                "SELECT host, first_seen, last_seen, spool_rows, spool_bytes"
                " FROM hosts ORDER BY host").fetchall()
            counts = dict(self.db.execute(
                "SELECT host, COUNT(*) FROM logs GROUP BY host").fetchall())
            nbytes = dict(self.db.execute(
                "SELECT host, SUM(blen) FROM logs GROUP BY host").fetchall())
        return [{"host": h, "first_seen": fs, "last_seen": ls,
                 "online": (now - ls) < 10, "spool_rows": sr, "spool_bytes": sb,
                 "logs": counts.get(h, 0), "bytes": nbytes.get(h, 0) or 0}
                for h, fs, ls, sr, sb in hrows]

    def files(self, host=None):
        sql = ("SELECT f.host, f.file_id, f.path, f.offset, f.size, f.done,"
               " (SELECT COUNT(*) FROM logs l WHERE l.host=f.host AND l.file_id=f.file_id),"
               " (SELECT COALESCE(SUM(blen),0) FROM logs l WHERE l.host=f.host AND l.file_id=f.file_id)"
               " FROM files f")
        args = ()
        if host:
            sql += " WHERE f.host=?"
            args = (host,)
        sql += " ORDER BY f.updated DESC LIMIT 1000"
        with self.lock:
            rows = self.db.execute(sql, args).fetchall()
        return [{"host": r[0], "file_id": r[1], "path": r[2], "offset": r[3],
                 "size": r[4], "done": r[5], "records": r[6], "received": r[7]}
                for r in rows]

    def gaps(self, host=None):
        out = []
        for f in self.files(host):
            with self.lock:
                ranges = self.db.execute(
                    "SELECT offset, blen FROM logs WHERE host=? AND file_id=?"
                    " ORDER BY offset", (f["host"], f["file_id"])).fetchall()
            expected = f["size"] if f["done"] else f["offset"]
            pos, missing = 0, []
            for off, blen in ranges:
                if off > pos:
                    missing.append([pos, off])
                pos = max(pos, off + blen)
            if pos < expected:
                missing.append([pos, expected])
            lag = max(0, f["size"] - pos)
            out.append({**f, "expected": expected, "covered": pos,
                        "missing": missing, "lag": lag,
                        "ok": not missing and lag == 0})
        return out

    def logs(self, host=None, file_id=None, limit=200):
        sql = ("SELECT host, file_id, path, offset, blen, text, ts FROM logs")
        cond, args = [], []
        if host:
            cond.append("host=?"); args.append(host)
        if file_id:
            cond.append("file_id=?"); args.append(file_id)
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY offset LIMIT ?" if file_id else " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with self.lock:
            rows = self.db.execute(sql, args).fetchall()
        return [{"host": r[0], "file_id": r[1], "path": r[2], "offset": r[3],
                 "blen": r[4], "text": r[5], "ts": r[6]} for r in rows]

    def stats(self):
        now = time.time()
        with self.lock:
            nhosts = self.db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            nfiles = self.db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            nlogs, nbytes = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(blen),0) FROM logs").fetchone()
        def rate(win):
            return sum(n for t, n in self.ingest_events if t > now - win) / win
        return {"hosts": nhosts, "files": nfiles, "logs": nlogs, "bytes": nbytes,
                "dups": self.dup_total, "rate10s": round(rate(10), 1),
                "rate60s": round(rate(60), 1),
                "db_bytes": os.path.getsize(self.dbpath) if os.path.exists(self.dbpath) else 0}


WEBUI = r"""
<title>logpipe 日志中心</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2129;--mut:#86909c;--line:#e5e6eb;--acc:#165dff;--ok:#00b42a;--bad:#f53f3f;--warn:#ff7d00}
:root:not([data-theme="light"]){color-scheme:light dark}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#17171a;--card:#232324;--fg:#e8e8e8;--mut:#8a8a8a;--line:#3a3a3c;--acc:#4e7cff}}
:root[data-theme="dark"]{--bg:#17171a;--card:#232324;--fg:#e8e8e8;--mut:#8a8a8a;--line:#3a3a3c;--acc:#4e7cff;color-scheme:dark}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
header{padding:14px 24px;background:var(--card);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:24px;flex-wrap:wrap}
h1{font-size:17px;margin:0}
nav{display:flex;gap:4px;flex-wrap:wrap}
nav button{border:0;background:none;color:var(--mut);padding:8px 14px;cursor:pointer;font-size:14px;border-radius:6px}
nav button.on{background:var(--acc);color:#fff}
main{padding:20px 24px;max-width:1280px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--mut);font-weight:500}
tr.bad td{color:var(--bad)}
tr.warn td{color:var(--warn)}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.pill.ok{background:rgba(0,180,42,.12);color:var(--ok)}
.pill.bad{background:rgba(245,63,63,.12);color:var(--bad)}
.stat{display:inline-block;margin:0 24px 8px 0}
.stat b{font-size:22px;display:block}
.stat span{color:var(--mut);font-size:12px}
textarea{width:100%;min-height:280px;font:12px/1.5 Consolas,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:10px}
button.act{background:var(--acc);color:#fff;border:0;padding:8px 18px;border-radius:6px;cursor:pointer}
pre.log{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;font:12px/1.45 Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:480px;overflow:auto;margin:8px 0 0}
select,input.sel{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px}
.mut{color:var(--mut)}
</style>
<header>
<h1>logpipe 日志采集中心</h1>
<nav id="nav"></nav>
<span class="mut" id="clock"></span>
</header>
<main>
<section id="tab-hosts" class="tab"><div class="card"><h3>主机清单</h3><div id="hosts"></div></div></section>
<section id="tab-config" class="tab"><div class="card"><h3>采集配置(中心下发,代理每 3 秒拉取)</h3>
<p class="mut">{"default": {...}} 为全局默认;"hosts": {"主机名": {...}} 按主机覆盖,globs 为通配路径,multiline 为首行正则。</p>
<textarea id="cfg"></textarea><p><button class="act" onclick="saveCfg()">保存并下发</button>
<span id="cfgmsg" class="mut"></span></p></div></section>
<section id="tab-transfer" class="tab"><div class="card"><h3>传输状态</h3><div id="transfer"></div></div></section>
<section id="tab-gaps" class="tab"><div class="card"><h3>丢失排查(按偏移区间比对)</h3><div id="gaps"></div></div></section>
<section id="tab-storage" class="tab"><div class="card"><h3>中心存储</h3><div id="storage"></div>
<p><select id="selhost" onchange="loadFiles()"></select> <select id="selfile" onchange="loadLogs()"></select>
<button class="act" onclick="loadLogs()">查看日志</button></p>
<pre class="log" id="logview">选择主机和文件后点击查看</pre></div></section>
</main>
<script>
const TABS=[["hosts","主机清单"],["config","采集配置"],["transfer","传输状态"],["gaps","丢失排查"],["storage","中心存储"]];
let cur="hosts";
const nav=document.getElementById("nav");
for(const [k,name] of TABS){
  const b=document.createElement("button");b.textContent=name;b.id="nav-"+k;
  b.onclick=()=>{cur=k;refresh()};nav.appendChild(b);
}
async function api(p,opt){const r=await fetch(p,opt);return r.json()}
function fmt(n){return n>=1e9?(n/1e9).toFixed(2)+"G":n>=1e6?(n/1e6).toFixed(2)+"M":n>=1e3?(n/1e3).toFixed(1)+"K":""+n}
function ago(ts){const s=Math.max(0,Date.now()/1e3-ts);return s<60?s.toFixed(0)+"秒前":s<3600?(s/60).toFixed(0)+"分钟前":(s/3600).toFixed(1)+"小时前"}
function tbl(head,rows){return "<table><tr>"+head.map(h=>"<th>"+h+"</th>").join("")+"</tr>"+rows.join("")+"</table>"}
async function refresh(){
  for(const [k] of TABS){
    document.getElementById("tab-"+k).hidden=k!==cur;
    document.getElementById("nav-"+k).className=k===cur?"on":"";
  }
  document.getElementById("clock").textContent=new Date().toLocaleTimeString();
  try{
    if(cur==="hosts")return loadHosts();
    if(cur==="config")return loadCfg();
    if(cur==="transfer")return loadTransfer();
    if(cur==="gaps")return loadGaps();
    if(cur==="storage")return loadStorage();
  }catch(e){console.log(e)}
}
async function loadHosts(){
  const hs=await api("/api/hosts");
  document.getElementById("hosts").innerHTML=tbl(
    ["主机","状态","最近心跳","本地缓冲(条)","本地缓冲(字节)","已收日志","已收字节"],
    hs.map(h=>"<tr><td>"+h.host+"</td><td>"+(h.online?'<span class="pill ok">在线</span>':'<span class="pill bad">离线</span>')+
      "</td><td>"+ago(h.last_seen)+"</td><td>"+h.spool_rows+"</td><td>"+fmt(h.spool_bytes)+
      "</td><td>"+fmt(h.logs)+"</td><td>"+fmt(h.bytes)+"</td></tr>"));
}
async function loadCfg(){
  const doc=await api("/api/configs");
  document.getElementById("cfg").value=JSON.stringify(doc,null,2);
}
async function saveCfg(){
  try{
    const doc=JSON.parse(document.getElementById("cfg").value);
    await api("/api/config",{method:"POST",body:JSON.stringify(doc)});
    document.getElementById("cfgmsg").textContent=" 已保存,代理将在数秒内生效";
  }catch(e){document.getElementById("cfgmsg").textContent=" JSON 解析失败: "+e}
}
async function loadTransfer(){
  const [st,hs]=await Promise.all([api("/api/stats"),api("/api/hosts")]);
  let h='<div><span class="stat"><b>'+st.rate10s+'</b><span>条/秒(10s)</span></span>'+
    '<span class="stat"><b>'+st.rate60s+'</b><span>条/秒(60s)</span></span>'+
    '<span class="stat"><b>'+fmt(st.dups)+'</b><span>去重拦截(重复)</span></span></div>';
  h+=tbl(["主机","链路","代理缓冲","已上报日志"],
    hs.map(h=>{const back=h.spool_rows>0;
      return '<tr class="'+(back?"warn":"")+'"><td>'+h.host+"</td><td>"+
      (h.online?'<span class="pill ok">通</span>':'<span class="pill bad">断/代理离线</span>')+"</td><td>"+
      h.spool_rows+" 条 / "+fmt(h.spool_bytes)+"B</td><td>"+fmt(h.logs)+"</td></tr>"}));
  document.getElementById("transfer").innerHTML=h;
}
async function loadGaps(){
  const gs=await api("/api/gaps");
  const bad=gs.filter(g=>!g.ok), ok=gs.filter(g=>g.ok);
  let h="<p>"+(bad.length?'<span class="pill bad">'+bad.length+" 个文件有缺口/滞后</span>":'<span class="pill ok">全部文件区间完整</span>')+
    ' <span class="mut">共 '+gs.length+' 个文件代际</span></p>';
  const rows=bad.concat(ok.slice(0,50)).map(g=>{
    const m=g.missing.slice(0,5).map(r=>"["+r[0]+","+r[1]+")").join(" ")+(g.missing.length>5?" …":"");
    return '<tr class="'+(g.missing.length?"bad":g.lag?"warn":"")+'"><td>'+g.host+"</td><td>"+g.path+
      "</td><td>"+g.file_id.slice(-12)+"</td><td>"+(g.done?"已封档":"采集中")+"</td><td>"+fmt(g.expected)+
      "</td><td>"+fmt(g.covered)+"</td><td>"+(g.missing.length?m:"-")+"</td><td>"+(g.lag?fmt(g.lag):"-")+"</td></tr>"});
  h+=tbl(["主机","文件","代际","状态","应有字节","已收字节","缺口区间","滞后"],rows);
  document.getElementById("gaps").innerHTML=h;
}
async function loadStorage(){
  const [st,hs]=await Promise.all([api("/api/stats"),api("/api/hosts")]);
  document.getElementById("storage").innerHTML=
    '<span class="stat"><b>'+st.hosts+'</b><span>主机</span></span>'+
    '<span class="stat"><b>'+st.files+'</b><span>文件代际</span></span>'+
    '<span class="stat"><b>'+fmt(st.logs)+'</b><span>日志记录</span></span>'+
    '<span class="stat"><b>'+fmt(st.bytes)+'</b><span>日志字节</span></span>'+
    '<span class="stat"><b>'+fmt(st.db_bytes)+'</b><span>存储占用</span></span>';
  const sh=document.getElementById("selhost");
  const old=sh.value;
  sh.innerHTML=hs.map(h=>'<option value="'+h.host+'">'+h.host+" ("+fmt(h.logs)+'条)</option>').join("");
  if(old)sh.value=old;
  if(sh.value)loadFiles();
}
async function loadFiles(){
  const host=document.getElementById("selhost").value;if(!host)return;
  const fs=await api("/api/files?host="+encodeURIComponent(host));
  const sf=document.getElementById("selfile");
  sf.innerHTML=fs.slice(0,100).map(f=>'<option value="'+f.file_id+'">'+f.path.split(/[\\/]/).pop()+" · "+f.file_id.slice(-8)+" · "+f.records+"条</option>").join("");
}
async function loadLogs(){
  const host=document.getElementById("selhost").value,fid=document.getElementById("selfile").value;
  if(!host||!fid)return;
  const ls=await api("/api/logs?host="+encodeURIComponent(host)+"&file_id="+encodeURIComponent(fid)+"&limit=300");
  document.getElementById("logview").textContent=ls.map(l=>"["+l.offset+"] "+l.text.replace(/\n+$/,"")).join("\n")||"(空)";
}
refresh();setInterval(refresh,2000);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "logpipe/1.0"

    def log_message(self, *a):
        pass

    @property
    def central(self):
        return self.server.central

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        c = self.central
        try:
            if u.path == "/":
                return self._send(200, WEBUI, "text/html; charset=utf-8")
            if u.path == "/api/hosts":
                return self._json(c.hosts())
            if u.path == "/api/files":
                return self._json(c.files(q.get("host", [None])[0]))
            if u.path == "/api/gaps":
                return self._json(c.gaps(q.get("host", [None])[0]))
            if u.path == "/api/logs":
                return self._json(c.logs(q.get("host", [None])[0],
                                         q.get("file_id", [None])[0],
                                         int(q.get("limit", [200])[0])))
            if u.path == "/api/stats":
                return self._json(c.stats())
            if u.path == "/api/config":
                return self._json(c.effective_config(q.get("host", [""])[0]))
            if u.path == "/api/configs":
                return self._json(c.get_doc())
            self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def do_POST(self):
        u = urlparse(self.path)
        c = self.central
        try:
            body = self._body()
            if u.path == "/api/ingest":
                acc, dup = c.ingest(body.get("host", "?"), body.get("records", []))
                return self._json({"ok": True, "accepted": acc, "dups": dup})
            if u.path == "/api/heartbeat":
                c.heartbeat(body.get("host", "?"), body.get("spool_rows", 0),
                            body.get("spool_bytes", 0), body.get("files", []))
                return self._json({"ok": True})
            if u.path == "/api/config":
                c.save_doc(body)
                return self._json({"ok": True})
            self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def main():
    ap = argparse.ArgumentParser(description="logpipe 中心端")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="central.db")
    args = ap.parse_args()

    central = Central(args.db)
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    srv.daemon_threads = True
    srv.central = central
    print("logpipe 中心端: http://0.0.0.0:%d  存储: %s" % (args.port, args.db), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
