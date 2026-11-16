"""logpipe 公共工具:默认配置、多行归并、共享句柄打开、文件身份标识。"""
from __future__ import annotations

import os
import re

DEFAULT_CONFIG = {
    "globs": [],                       # 通配路径列表,如 ["/var/log/app/*.log*"]
    "multiline": r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",  # 首行特征(时间戳开头)
    "multiline_timeout": 1.0,          #  pending 记录空闲多久后强制封口(秒)
    "scan_interval": 0.25,             # 目录扫描间隔(秒)
    "spool_max_bytes": 64 * 1024 * 1024,  # 本地磁盘缓冲上限,超限反压(暂停读取)
    "batch_size": 500,                 # 每批发送记录数
    "close_inactive": 5.0,             # 文件读完且空闲多久后关闭句柄(秒)
    "gone_timeout": 10.0,              # 文件从通配结果中消失多久后判定已删除(秒)
    "heartbeat_interval": 2.0,         # 心跳间隔(秒)
    "config_interval": 3.0,            # 向中心拉取配置的间隔(秒)
}


def open_shared(path):
    """以完全共享(读/写/删除)方式打开文件只读句柄。

    Windows 上普通 open() 不允许其他进程 rename/delete 该文件,
    会卡住日志轮转;这里用 CreateFileW 显式带上 FILE_SHARE_DELETE。
    """
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import msvcrt

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        GENERIC_READ = 0x80000000
        SHARE_ALL = 0x1 | 0x2 | 0x4          # READ | WRITE | DELETE
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        handle = kernel32.CreateFileW(
            str(path), GENERIC_READ, SHARE_ALL, None,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        invalid = wintypes.HANDLE(-1).value
        if handle is None or handle == invalid:
            raise OSError("CreateFileW failed, gle=%d" % ctypes.GetLastError())
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        return os.fdopen(fd, "rb")
    return open(path, "rb")


def st_birth_ns(st):
    """文件'出生'时间(Windows 上 st_ctime 即创建时间),用于区分 inode 复用。"""
    return getattr(st, "st_ctime_ns", int(st.st_ctime * 1e9))


def make_file_id(dev, ino, birth, gen):
    """文件身份 = 设备.inode.出生时间.代际号。

    - 同名新文件:inode/出生时间不同 → 不同 file_id
    - 截断/copytruncate:同一 inode 内容从头再来 → 代际号 +1
    """
    return "%x.%x.%x.g%d" % (dev, ino, birth, gen)


class RecordAssembler:
    """多行归并:按首行特征把跨行日志(如 Java 堆栈)拼成一条记录。

    喂入完整行(含换行符的字节)及其在文件中的起始偏移,
    产出 (记录起始偏移, 记录字节)。不匹配首行特征的行并入上一条。
    """

    __slots__ = ("re", "pend", "pend_start")

    def __init__(self, pattern):
        self.re = re.compile(pattern)
        self.pend = None        # 待封口记录的字节
        self.pend_start = 0     # 待封口记录的起始偏移

    def feed(self, line, start):
        is_start = bool(self.re.match(line.decode("utf-8", "replace")))
        if is_start:
            out = None
            if self.pend is not None:
                out = (self.pend_start, self.pend)
            self.pend = line
            self.pend_start = start
            return out
        if self.pend is None:
            # 文件开头就是续行(孤儿行),自起一条
            self.pend = line
            self.pend_start = start
            return None
        self.pend += line
        return None

    def flush(self):
        if self.pend is None:
            return None
        out = (self.pend_start, self.pend)
        self.pend = None
        return out
