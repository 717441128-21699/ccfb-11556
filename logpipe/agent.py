"""logpipe 采集代理。

职责:
  1. 按通配路径盯文件,新文件出现自动加入;
  2. 识别轮转(改名 / 截断 / copytruncate),不丢不重;
  3. 读取位点持久化在本地 SQLite,重启后续读;同名新文件按 (dev,ino,birth,gen) 区分;
  4. 多行归并(Java 堆栈等跨行日志归为一条);
  5. 中心不可达时写本地 SQLite spool 缓冲,有上限,超限反压暂停读取;
  6. 每条记录带 (host, file_id, offset),中心按此三元组去重;
  7. 断网恢复后按 spool 主键顺序补发。

关键不变式:记录写入 spool 与位点推进在同一个 SQLite 事务里提交,
因此进程在任意时刻被杀,重启后状态都一致 —— 已入 spool 的会补发,
未入 spool 的会按位点重读,中心端再去重兜底。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sqlite3
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request

from .common import DEFAULT_CONFIG, RecordAssembler, make_file_id, open_shared, st_birth_ns

CHUNK = 256 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS spool(
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT NOT NULL,
  path    TEXT NOT NULL,
  offset  INTEGER NOT NULL,
  blen    INTEGER NOT NULL,
  text    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files(
  file_id TEXT PRIMARY KEY,
  path    TEXT NOT NULL,
  dev     TEXT NOT NULL,
  ino     TEXT NOT NULL,
  birth   TEXT NOT NULL,
  gen     INTEGER NOT NULL,
  offset  INTEGER NOT NULL DEFAULT 0,
  size    INTEGER NOT NULL DEFAULT 0,
  mtime   INTEGER NOT NULL DEFAULT 0,
  tail    BLOB,
  done    INTEGER NOT NULL DEFAULT 0,
  updated REAL
);
CREATE INDEX IF NOT EXISTS idx_files_devino ON files(dev, ino, birth);
"""


def http_json(method, url, payload=None, timeout=8.0):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class Reader(object):
    """一个被跟踪的物理文件(按 dev+ino 区分)的读取状态。"""

    __slots__ = ("key", "file_id", "path", "handle", "birth", "gen",
                 "read_pos", "size", "buf", "asm", "last_data", "seen",
                 "tail", "ckpt_tail")

    def __init__(self, key, file_id, path, handle, birth, gen, read_pos,
                 multiline, tail=b""):
        self.key = key                # (dev, ino)
        self.file_id = file_id
        self.path = path
        self.handle = handle
        self.birth = birth
        self.gen = gen
        self.read_pos = read_pos      # 已从句柄读到的位置(含 buf/pending 未提交部分)
        self.size = 0
        self.buf = b""                # 读到但尚未凑满一行的字节
        self.asm = RecordAssembler(multiline)
        self.last_data = time.time()  # 最后一次读到新数据的时间
        self.seen = time.time()       # 最后一次在通配扫描中看到该文件的时间
        self.tail = tail              # read_pos 之前最近 64 字节(截断指纹)
        self.ckpt_tail = tail         # 已提交位点之前最近 64 字节(持久化)


class Agent(object):
    def __init__(self, host, server, workdir, local_cfg=None):
        self.host = host
        self.server = server.rstrip("/")
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)

        # 配置优先级:默认值 < 缓存的中心配置 < 本地配置文件 < 中心实时下发
        self.cfg = dict(DEFAULT_CONFIG)
        cache = os.path.join(workdir, "config_cache.json")
        self._cache_path = cache
        if os.path.exists(cache):
            try:
                with open(cache, "r", encoding="utf-8") as f:
                    self.cfg.update(json.load(f))
            except Exception:
                pass
        if local_cfg:
            self.cfg.update(local_cfg)
        self.cfg_lock = threading.Lock()

        self.stop_event = threading.Event()
        self.readers = {}             # (dev, ino) -> Reader
        self.net_ok = False
        self.sent_total = 0

        self.db = sqlite3.connect(os.path.join(workdir, "agent.db"),
                                  check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")  # 进程被杀不丢已提交数据
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self.db_lock = threading.RLock()
        with self.db_lock:
            row = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(blen),0) FROM spool").fetchone()
        self.spool_rows, self.spool_bytes = int(row[0]), int(row[1])

    def log(self, msg):
        print("[%s][%s] %s" % (time.strftime("%H:%M:%S"), self.host, msg), flush=True)

    def get_cfg(self):
        with self.cfg_lock:
            return dict(self.cfg)

    # ---------------- 扫描:发现新文件 / 恢复续读 ----------------

    def scan(self):
        cfg = self.get_cfg()
        paths = set()
        for pat in cfg.get("globs") or []:
            try:
                paths.update(glob.glob(pat))
            except Exception:
                pass
        now = time.time()
        for path in sorted(paths):
            apath = os.path.normpath(path)
            try:
                st = os.stat(apath)
            except OSError:
                continue
            if not os.path.isfile(apath):
                continue
            key = (st.st_dev, st.st_ino)
            r = self.readers.get(key)
            if r is not None:
                if r.path != apath:
                    # 改名轮转:路径变了,刷新库里的路径(供位点核对与排查)
                    r.path = apath
                    with self.db_lock, self.db:
                        self.db.execute(
                            "UPDATE files SET path=?, updated=? WHERE file_id=?",
                            (apath, time.time(), r.file_id))
                r.seen = now
                continue
            birth = st_birth_ns(st)
            # ReFS 上 st_ino 是 128 位,超出 SQLite int64,统一按字符串存
            sdev, sino, sbirth = str(st.st_dev), str(st.st_ino), str(birth)
            with self.db_lock:
                row = self.db.execute(
                    "SELECT file_id, gen, offset, done, tail, mtime FROM files "
                    "WHERE dev=? AND ino=? AND birth=? ORDER BY gen DESC LIMIT 1",
                    (sdev, sino, sbirth)).fetchone()
            if row:
                file_id, gen, offset, done, tail, mtime = row
                if done:
                    continue                      # 已读完封档的老文件
                if st.st_size == offset and st.st_mtime_ns == mtime:
                    continue                      # 没动过,不必打开
                # 否则:重启续读 / 关闭期间有变化(追加或截断,由指纹判定)
                tail = tail or b""
            else:
                file_id, gen, offset, tail = \
                    make_file_id(st.st_dev, st.st_ino, birth, 0), 0, 0, b""
            try:
                handle = open_shared(apath)
            except OSError:
                continue
            handle.seek(offset)
            r = Reader(key, file_id, apath, handle, birth, gen, offset,
                       cfg["multiline"], tail=tail)
            self.readers[key] = r
            self.upsert_file(r, done=0)
            self.log("跟踪 %s (file_id=%s, offset=%d)" % (apath, file_id, offset))

    def upsert_file(self, r, done):
        try:
            mtime = os.fstat(r.handle.fileno()).st_mtime_ns
        except OSError:
            mtime = 0
        with self.db_lock, self.db:
            self.db.execute(
                "INSERT INTO files(file_id,path,dev,ino,birth,gen,offset,size,"
                " mtime,tail,done,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(file_id) DO UPDATE SET path=excluded.path,"
                " offset=excluded.offset, size=excluded.size,"
                " mtime=excluded.mtime, done=excluded.done, updated=excluded.updated",
                (r.file_id, r.path, str(r.key[0]), str(r.key[1]), str(r.birth),
                 r.gen, r.read_pos, r.size, mtime,
                 sqlite3.Binary(r.ckpt_tail), done, time.time()))

    # ---------------- 读取:轮转识别 + 多行归并 + 提交 ----------------

    def read_pass(self, r, cfg):
        now = time.time()
        try:
            size = os.fstat(r.handle.fileno()).st_size
        except OSError:
            self.close_reader(r, done=1)
            return

        truncated = size < r.read_pos
        if not truncated and r.read_pos > 0 and r.tail:
            # 截断后迅速重写会绕过 size<read_pos 检查;
            # 校验 read_pos 之前的字节指纹,对不上说明内容被换过
            k = min(len(r.tail), r.read_pos)
            try:
                r.handle.seek(r.read_pos - k)
                chunk = r.handle.read(k)
            except OSError:
                chunk = None
            if chunk != r.tail[-k:]:
                truncated = True

        if truncated:
            # 截断 / copytruncate:老一代收尾封档,同一 inode 开新一代
            self.log("检测到截断: %s (read_pos=%d, size=%d), 开新一代"
                     % (r.path, r.read_pos, size))
            self.commit_pending(r)
            self.commit_buf(r)
            with self.db_lock, self.db:
                self.db.execute(
                    "UPDATE files SET done=1, size=?, offset=?, updated=? WHERE file_id=?",
                    (r.read_pos, r.read_pos, now, r.file_id))
            r.gen += 1
            r.file_id = make_file_id(r.key[0], r.key[1], r.birth, r.gen)
            r.read_pos = 0
            r.buf = b""
            r.tail = r.ckpt_tail = b""
            r.asm = RecordAssembler(cfg["multiline"])
            try:
                r.handle.seek(0)
            except OSError:
                pass
            self.upsert_file(r, done=0)
            size = 0

        r.size = size
        if size > r.read_pos:
            try:
                r.handle.seek(r.read_pos)
                data = r.handle.read(min(CHUNK, size - r.read_pos))
            except OSError:
                data = b""
            if data:
                r.last_data = now
                r.buf += data
                r.read_pos += len(data)
                r.tail = (r.tail + data)[-64:]
                self.process_buf(r, cfg)

        idle = now - r.last_data
        if r.asm.pend is not None and idle >= float(cfg["multiline_timeout"]):
            self.commit_pending(r)               # 多行记录空闲超时,封口提交

        gone = (now - r.seen) >= float(cfg["gone_timeout"])
        if r.read_pos == r.size and r.asm.pend is None:
            if r.buf and gone:
                self.commit_buf(r)               # 文件已删,残留半行也提交
            if not r.buf and (idle >= float(cfg["close_inactive"]) or gone):
                self.close_reader(r, done=1 if gone else 0)

    def process_buf(self, r, cfg):
        data = r.buf
        base = r.read_pos - len(data)
        pos = 0
        while True:
            i = data.find(b"\n", pos)
            if i < 0:
                break
            line = data[pos:i + 1]
            rec = r.asm.feed(line, base + pos)
            if rec is not None:
                self.store_record(r, rec[0], rec[1])
            pos = i + 1
        r.buf = data[pos:]

    def store_record(self, r, start, b):
        """记录写入 spool 并推进位点,同一事务提交;spool 超限则反压等待。"""
        cap = int(self.get_cfg()["spool_max_bytes"])
        while True:
            with self.db_lock:
                used = self.spool_bytes
            if used + len(b) <= cap:
                break
            if self.stop_event.is_set():
                return
            time.sleep(0.2)
        text = b.decode("utf-8", "replace")
        end = start + len(b)
        r.ckpt_tail = (r.ckpt_tail + b)[-64:]
        with self.db_lock, self.db:
            self.db.execute(
                "INSERT INTO spool(file_id,path,offset,blen,text) VALUES(?,?,?,?,?)",
                (r.file_id, r.path, start, len(b), text))
            self.db.execute(
                "UPDATE files SET offset=?, size=?, tail=?, updated=? WHERE file_id=?",
                (end, r.size, sqlite3.Binary(r.ckpt_tail), time.time(), r.file_id))
            self.spool_rows += 1
            self.spool_bytes += len(b)

    def commit_pending(self, r):
        rec = r.asm.flush()
        if rec is not None:
            self.store_record(r, rec[0], rec[1])

    def commit_buf(self, r):
        if r.buf:
            start = r.read_pos - len(r.buf)
            b, r.buf = r.buf, b""
            self.store_record(r, start, b)

    def close_reader(self, r, done):
        self.commit_pending(r)
        self.commit_buf(r)
        try:
            mtime = os.fstat(r.handle.fileno()).st_mtime_ns
        except OSError:
            mtime = 0
        with self.db_lock, self.db:
            self.db.execute(
                "UPDATE files SET done=?, size=?, offset=?, mtime=?, updated=?"
                " WHERE file_id=?",
                (done, r.read_pos, r.read_pos, mtime, time.time(), r.file_id))
        try:
            r.handle.close()
        except OSError:
            pass
        self.readers.pop(r.key, None)

    # ---------------- 发送:按 spool 顺序,确认后删除 ----------------

    def sender_loop(self):
        backoff = 0.2
        cfg = self.get_cfg()
        while not self.stop_event.is_set():
            with self.db_lock:
                rows = self.db.execute(
                    "SELECT id,file_id,path,offset,blen,text FROM spool"
                    " ORDER BY id LIMIT ?", (int(cfg["batch_size"]),)).fetchall()
            if not rows:
                time.sleep(0.2)
                continue
            payload = {"host": self.host, "records": [
                {"file_id": r[1], "path": r[2], "offset": r[3],
                 "blen": r[4], "text": r[5]} for r in rows]}
            try:
                http_json("POST", self.server + "/api/ingest", payload, timeout=10.0)
            except Exception:
                self.net_ok = False
                time.sleep(backoff)
                backoff = min(5.0, backoff * 2)
                continue
            backoff = 0.2
            self.net_ok = True
            last_id = rows[-1][0]
            with self.db_lock, self.db:
                self.db.execute("DELETE FROM spool WHERE id<=?", (last_id,))
                row = self.db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(blen),0) FROM spool").fetchone()
                self.spool_rows, self.spool_bytes = int(row[0]), int(row[1])
            self.sent_total += len(rows)

    # ---------------- 心跳 / 配置下发 ----------------

    def heartbeat_loop(self):
        while not self.stop_event.is_set():
            cfg = self.get_cfg()
            try:
                with self.db_lock:
                    files = [{"file_id": r[0], "path": r[1], "offset": r[2],
                              "size": r[3], "done": r[4]} for r in self.db.execute(
                        "SELECT file_id,path,offset,size,done FROM files"
                        " ORDER BY updated DESC LIMIT 500")]
                    spool_rows, spool_bytes = self.spool_rows, self.spool_bytes
                http_json("POST", self.server + "/api/heartbeat", {
                    "host": self.host, "ts": time.time(),
                    "spool_rows": spool_rows, "spool_bytes": spool_bytes,
                    "sent_total": self.sent_total, "files": files}, timeout=5.0)
            except Exception:
                pass
            self.stop_event.wait(float(cfg["heartbeat_interval"]))

    def config_loop(self):
        while not self.stop_event.is_set():
            cfg = self.get_cfg()
            try:
                eff = http_json("GET", self.server + "/api/config?host="
                                + urllib.parse.quote(self.host), timeout=5.0)
                if isinstance(eff, dict) and eff:
                    with self.cfg_lock:
                        self.cfg.update(eff)
                    try:
                        with open(self._cache_path, "w", encoding="utf-8") as f:
                            json.dump(eff, f)
                    except OSError:
                        pass
            except Exception:
                pass
            self.stop_event.wait(float(cfg["config_interval"]))

    # ---------------- 主循环 ----------------

    def run(self):
        self.log("启动, server=%s workdir=%s globs=%s"
                 % (self.server, self.workdir, self.get_cfg().get("globs")))
        for target in (self.sender_loop, self.heartbeat_loop, self.config_loop):
            threading.Thread(target=target, daemon=True).start()
        while not self.stop_event.is_set():
            cfg = self.get_cfg()
            try:
                self.scan()
                for r in list(self.readers.values()):
                    self.read_pass(r, cfg)
            except Exception:
                traceback.print_exc()
            self.stop_event.wait(float(cfg["scan_interval"]))


def main():
    ap = argparse.ArgumentParser(description="logpipe 采集代理")
    ap.add_argument("--host", required=True, help="主机名(上报标识)")
    ap.add_argument("--server", required=True, help="中心地址,如 http://127.0.0.1:8765")
    ap.add_argument("--workdir", required=True, help="工作目录(spool/位点库)")
    ap.add_argument("--config", help="本地配置文件(JSON,中心不可达时的兜底)")
    args = ap.parse_args()

    local_cfg = None
    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as f:
            local_cfg = json.load(f)

    agent = Agent(args.host, args.server, args.workdir, local_cfg)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop_event.set()


if __name__ == "__main__":
    main()
