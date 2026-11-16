#!/usr/bin/env python3
"""logpipe 压测:N 台机器疯狂写日志 + 频繁轮转 + 随机杀代理 + 随机断网,
最后把中心收到的数据与源端流水账逐条核对,一条不差才算过。

用法: python stress_test.py [--hosts 30] [--duration 90] [--port 18765]

结构:
  中心端(子进程) <-- ChaosProxy(可随时掐断) <-- N 个代理(子进程,随机被杀)
  N 个写入线程模拟应用:写 app.log,按大小轮转(rename / truncate / copytruncate),
  偶尔开新文件 extra-K.log;每写一条记录同时记入 truth.jsonl 流水账。

说明:truncate/copytruncate 会把文件内容就地销毁,任何采集器(包括 filebeat)
都无法在"应用已截断而采集器还没读到"时找回数据,所以写入线程在做破坏性
轮转前会等代理追上(读代理的位点库),追不上(代理正被杀)就跳过本次破坏性
轮转 —— rename 轮转无此限制,随时可做。
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))


def log(msg):
    print("[%s][stress] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# ---------------- 可掐断的 TCP 代理(模拟断网) ----------------

class ChaosProxy(object):
    def __init__(self, listen_port, target_port):
        self.listen_port = listen_port
        self.target_port = target_port
        self.up = True
        self.lock = threading.Lock()
        self.conns = set()
        self.lsock = None
        self.stopped = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self.stopped:
            with self.lock:
                if self.up and self.lsock is None:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("127.0.0.1", self.listen_port))
                    s.listen(256)
                    s.settimeout(0.5)
                    self.lsock = s
                ls = self.lsock if self.up else None
            if ls is None:
                time.sleep(0.1)
                continue
            try:
                c, _ = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.1)
                continue
            with self.lock:
                self.conns.add(c)
            threading.Thread(target=self._pipe, args=(c,), daemon=True).start()

    def _pipe(self, c):
        t = None
        try:
            t = socket.create_connection(("127.0.0.1", self.target_port), timeout=5)
            with self.lock:
                self.conns.add(t)

            def fwd(a, b):
                try:
                    while True:
                        d = a.recv(65536)
                        if not d:
                            break
                        b.sendall(d)
                except OSError:
                    pass
                finally:
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            threading.Thread(target=fwd, args=(t, c), daemon=True).start()
            fwd(c, t)
        except OSError:
            try:
                c.close()
            except OSError:
                pass
        finally:
            with self.lock:
                self.conns.discard(c)
                if t is not None:
                    self.conns.discard(t)

    def set_up(self, flag):
        with self.lock:
            self.up = flag
            if not flag:
                ls, self.lsock = self.lsock, None
                conns = list(self.conns)
                self.conns.clear()
            else:
                ls, conns = None, []
        if ls is not None:
            try:
                ls.close()
            except OSError:
                pass
        for s in conns:
            try:
                s.close()
            except OSError:
                pass

    def close(self):
        self.stopped = True
        self.set_up(False)


# ---------------- 应用日志写入线程 ----------------

class HostWriter(threading.Thread):
    def __init__(self, host, hdir, stop_event, seed):
        super().__init__(daemon=True)
        self.host = host
        self.hdir = hdir
        self.logs_dir = os.path.join(hdir, "logs")
        self.archive_dir = os.path.join(hdir, "archive")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.archive_dir, exist_ok=True)
        self.app = os.path.normpath(os.path.join(self.logs_dir, "app.log"))
        self.agent_db = os.path.join(hdir, "agent", "agent.db")
        self.stop_event = stop_event
        self.rnd = random.Random(seed)
        self.seq = 0
        self.rotations = 0
        self.skipped_rotations = 0
        self.rotate_at = self.rnd.randint(4096, 16384)
        self.extra_n = 0
        self.min_gen = {}             # (dev,ino) -> 代理必须超过的代际号
        self.journal_path = os.path.join(hdir, "truth.jsonl")
        self.journal = open(self.journal_path, "a", encoding="utf-8")

    def make_record(self):
        self.seq += 1
        r = self.rnd
        ts = time.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % r.randint(0, 999)
        first = "%s INFO  [worker-%d] host=%s seq=%d 处理请求 path=/api/%d 中文内容-%d" % (
            ts, r.randint(1, 8), self.host, self.seq, r.randint(0, 9999), self.seq)
        lines = [first]
        if r.random() < 0.3:  # 30% 概率带多行堆栈
            lines.append("java.lang.RuntimeException: 模拟异常 seq=%d" % self.seq)
            for _ in range(r.randint(2, 6)):
                lines.append("\tat com.example.app.Class%d.method%d(Class%d.java:%d)" % (
                    r.randint(1, 9), r.randint(1, 9), r.randint(1, 9), r.randint(1, 500)))
            if r.random() < 0.5:
                lines.append("Caused by: java.io.IOException: 磁盘抖动 seq=%d" % self.seq)
                lines.append("\tat com.example.io.Store.write(Store.java:88)")
        return "\n".join(lines) + "\n"

    def write_burst(self, path):
        n = self.rnd.randint(1, 15)
        with open(path, "ab") as f:
            for _ in range(n):
                rec = self.make_record()
                f.write(rec.encode("utf-8"))
                self.journal.write(json.dumps(
                    {"seq": self.seq, "text": rec}, ensure_ascii=False) + "\n")

    def agent_caught_up(self, timeout=15.0):
        """等代理追平 app.log 当前这一代,返回 (inode键, 代理当前代际号);超时返回 None。

        两道防线缺一不可:
        1. 按当前文件的 dev/ino 精确匹配位点行(老文件改名后路径会骗人);
        2. 要求代理的代际号 gen 大于本写入线程上次破坏性轮转时见到的 gen ——
           截断不换 inode,代理还没发现上一次截断时,行里留的是上一代的
           大位点,而新文件还小,一比就"假追平"。
        """
        try:
            st = os.stat(self.app)
        except OSError:
            return None
        key = (str(st.st_dev), str(st.st_ino))
        target = st.st_size
        min_gen = self.min_gen.get(key, -1)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                con = sqlite3.connect("file:%s?mode=ro" % self.agent_db,
                                      uri=True, timeout=1)
                rows = con.execute(
                    "SELECT gen, offset FROM files WHERE dev=? AND ino=? AND done=0"
                    " ORDER BY gen DESC LIMIT 1", key).fetchall()
                con.close()
            except sqlite3.Error:
                rows = []
            if rows and rows[0][0] > min_gen and rows[0][1] >= target:
                return key, rows[0][0]
            time.sleep(0.1)
        return None

    def maybe_rotate(self):
        try:
            size = os.path.getsize(self.app)
        except OSError:
            return
        if size < self.rotate_at:
            return
        self.rotate_at = self.rnd.randint(4096, 16384)
        kind = self.rnd.choices(["rename", "truncate", "copytruncate"],
                                weights=[5, 2, 3])[0]
        if kind == "rename":
            dst = os.path.join(self.logs_dir, "app.log.%d.%d" % (
                int(time.time() * 1000), self.rotations))
            try:
                os.rename(self.app, dst)   # 留在 logs/ 下,仍被通配匹配
            except OSError:
                return
        else:
            # 破坏性轮转:必须确认代理已追平当前代际,否则数据已被销毁,
            # 谁也救不回;追不上(代理正被杀)就跳过本次。
            caught = self.agent_caught_up()
            if caught is None:
                self.skipped_rotations += 1
                return
            key, gen = caught
            if kind == "copytruncate":
                shutil.copyfile(self.app, os.path.join(
                    self.archive_dir, "app.%d.%d.log" % (
                        int(time.time() * 1000), self.rotations)))
            with open(self.app, "wb"):
                pass
            # 代理发现这次截断前,不允许下一次破坏性轮转骗过追平检查
            self.min_gen[key] = gen
        self.rotations += 1

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.write_burst(self.app)
                self.maybe_rotate()
                if self.rnd.random() < 0.04:  # 4% 概率开新文件,考察新文件自动发现
                    self.extra_n += 1
                    extra = os.path.join(self.logs_dir, "extra-%d.log" % self.extra_n)
                    self.write_burst(extra)
            except Exception as e:  # 轮转瞬间的瞬态错误,下一拍重试
                log("%s 写入异常(忽略): %r" % (self.host, e))
            time.sleep(self.rnd.uniform(0.01, 0.06))
        self.journal.flush()
        self.journal.close()


# ---------------- 子进程封装 ----------------

class Proc(object):
    def __init__(self, name, argv, logpath):
        self.name = name
        self.argv = argv
        self.logpath = logpath
        self.proc = None

    def start(self):
        self._logf = open(self.logpath, "ab", buffering=0)
        self.proc = subprocess.Popen(self.argv, stdout=self._logf,
                                     stderr=subprocess.STDOUT, cwd=ROOT)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def kill(self):
        if self.alive():
            self.proc.kill()          # 模拟宕机:不给任何清理机会
            self.proc.wait()

    def stop(self):
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def http_get(url, timeout=5.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def http_post(url, payload, timeout=5.0):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ---------------- 主流程 ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=30)
    ap.add_argument("--duration", type=float, default=90, help="混沌阶段秒数")
    ap.add_argument("--port", type=int, default=18765)
    ap.add_argument("--workdir", default=os.path.join(ROOT, "stress_run"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    workdir = os.path.abspath(args.workdir)
    if os.path.exists(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir)
    cport, pport = args.port, args.port + 1
    server_via_proxy = "http://127.0.0.1:%d" % pport

    # 1. 中心端
    central = Proc("central", [sys.executable, "-m", "logpipe.central",
                               "--port", str(cport),
                               "--db", os.path.join(workdir, "central.db")],
                   os.path.join(workdir, "central.log"))
    central.start()
    for _ in range(100):
        try:
            http_get("http://127.0.0.1:%d/api/stats" % cport, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("中心端启动失败")
    log("中心端已启动 :%d" % cport)

    # 2. 下发采集配置(每台主机各自的通配路径)
    hosts = ["host-%02d" % i for i in range(args.hosts)]
    doc = {"default": {
        "multiline": r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        "multiline_timeout": 1.0, "scan_interval": 0.25,
        "spool_max_bytes": 32 * 1024 * 1024, "batch_size": 500,
        "close_inactive": 5.0, "gone_timeout": 10.0,
        "heartbeat_interval": 2.0, "config_interval": 3.0},
        "hosts": {}}
    for h in hosts:
        hdir = os.path.join(workdir, h)
        os.makedirs(os.path.join(hdir, "logs"), exist_ok=True)
        doc["hosts"][h] = {"globs": [os.path.join(hdir, "logs", "*.log*")]}
    http_post("http://127.0.0.1:%d/api/config" % cport, doc)
    log("采集配置已下发(%d 台主机)" % len(hosts))

    # 3. 断网代理 + 采集代理
    proxy = ChaosProxy(pport, cport)
    agents = {}
    for h in hosts:
        hdir = os.path.join(workdir, h)
        cfgpath = os.path.join(hdir, "agent.json")
        with open(cfgpath, "w", encoding="utf-8") as f:
            json.dump(doc["hosts"][h] | doc["default"], f)
        p = Proc(h, [sys.executable, "-m", "logpipe.agent",
                     "--host", h, "--server", server_via_proxy,
                     "--workdir", os.path.join(hdir, "agent"),
                     "--config", cfgpath],
                 os.path.join(hdir, "agent.log"))
        p.start()
        agents[h] = p
    log("%d 个代理已启动(经 ChaosProxy :%d)" % (len(agents), pport))

    # 4. 写入线程
    stop_writers = threading.Event()
    stop_chaos = threading.Event()
    writers = [HostWriter(h, os.path.join(workdir, h), stop_writers, rnd.randint(0, 1 << 30))
               for h in hosts]
    for w in writers:
        w.start()
    log("%d 个写入线程已启动" % len(writers))

    # 5. 混沌:随机杀代理、随机断网
    stats = {"kills": 0, "netcuts": 0}

    def chaos():
        while not stop_chaos.is_set():
            time.sleep(rnd.uniform(4, 9))
            if stop_chaos.is_set():
                break
            if rnd.random() < 0.6:
                h = rnd.choice(hosts)
                a = agents[h]
                if a.alive():
                    a.kill()
                    stats["kills"] += 1
                    log("杀掉代理 %s (第 %d 次)" % (h, stats["kills"]))
                    delay = rnd.uniform(2, 6)
                    threading.Timer(delay, lambda p=a: (
                        not stop_chaos.is_set()) and not p.alive() and p.start()).start()
            else:
                proxy.set_up(False)
                stats["netcuts"] += 1
                log("断网 (第 %d 次)" % stats["netcuts"])
                time.sleep(rnd.uniform(2, 6))
                proxy.set_up(True)
                log("网络恢复")

    threading.Thread(target=chaos, daemon=True).start()

    # 6. 跑满时长
    log("混沌阶段 %ds ..." % args.duration)
    time.sleep(args.duration)
    stop_chaos.set()
    proxy.set_up(True)
    stop_writers.set()
    for w in writers:
        w.join()
    log("写入结束:轮转 %d 次,跳过破坏性轮转 %d 次,杀代理 %d 次,断网 %d 次" % (
        sum(w.rotations for w in writers),
        sum(w.skipped_rotations for w in writers),
        stats["kills"], stats["netcuts"]))

    # 7. 唤醒所有代理,等待排空
    for a in agents.values():
        if not a.alive():
            a.start()
    truth_total = 0
    for h in hosts:
        with open(os.path.join(workdir, h, "truth.jsonl"), encoding="utf-8") as f:
            truth_total += sum(1 for _ in f)
    log("源端共 %d 条记录,等待中心排空 ..." % truth_total)
    deadline = time.time() + 300
    got = 0
    while time.time() < deadline:
        try:
            got = http_get("http://127.0.0.1:%d/api/stats" % cport)["logs"]
        except Exception:
            got = -1
        if got >= truth_total:
            break
        time.sleep(2)
    log("中心已收 %d / %d 条" % (got, truth_total))

    # 8. 收尾前看一眼缺口页
    try:
        gaps = http_get("http://127.0.0.1:%d/api/gaps" % cport, timeout=30)
        open_gaps = [g for g in gaps if g["missing"]]
    except Exception as e:
        gaps, open_gaps = [], [{"path": "gaps 查询失败: %r" % e}]

    for a in agents.values():
        a.stop()
    central.stop()
    proxy.close()

    # 9. 逐条核对
    log("开始逐条核对 ...")
    db = sqlite3.connect(os.path.join(workdir, "central.db"))
    fail = 0
    total_lines_truth = total_lines_got = 0
    for h in hosts:
        truth = []
        with open(os.path.join(workdir, h, "truth.jsonl"), encoding="utf-8") as f:
            for line in f:
                truth.append(json.loads(line)["text"])
        got_texts = [r[0] for r in db.execute(
            "SELECT text FROM logs WHERE host=?", (h,))]
        ct, cg = collections.Counter(truth), collections.Counter(got_texts)
        missing = ct - cg
        extra = cg - ct
        lt = sum(t.count("\n") for t in truth)
        lg = sum(t.count("\n") for t in got_texts)
        total_lines_truth += lt
        total_lines_got += lg
        if missing or extra:
            fail += 1
            log("  [FAIL] %s: 缺 %d 条 / 多 %d 条 (行 %d vs %d)" % (
                h, sum(missing.values()), sum(extra.values()), lt, lg))
            for t, n in list(missing.items())[:3]:
                log("    缺 x%d: %r" % (n, t[:120]))
            for t, n in list(extra.items())[:3]:
                log("    多 x%d: %r" % (n, t[:120]))
        else:
            log("  [OK]   %s: %d 条记录 / %d 行,逐条一致" % (h, len(truth), lt))
    nfiles = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    db.close()

    log("=" * 60)
    log("主机 %d 台,文件代际 %d 个,记录 %d 条,日志行 %d 行" % (
        len(hosts), nfiles, truth_total, total_lines_truth))
    log("杀代理 %d 次,断网 %d 次,轮转 %d 次(跳过 %d 次)" % (
        stats["kills"], stats["netcuts"],
        sum(w.rotations for w in writers),
        sum(w.skipped_rotations for w in writers)))
    if open_gaps:
        log("[FAIL] 中心缺口页仍有 %d 个文件存在缺口,例如: %s" % (
            len(open_gaps), open_gaps[0]))
        fail += 1
    if fail:
        log("结果: 失败,%d 项不符" % fail)
        return 1
    if total_lines_got != total_lines_truth:
        log("结果: 失败,行数不符 %d != %d" % (total_lines_got, total_lines_truth))
        return 1
    log("结果: 全部一致,一行不差 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
