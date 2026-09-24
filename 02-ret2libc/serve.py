#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地模拟"远程"服务：监听 9999，每个连接 fork 一个 vuln2 进程做双向管道。
用于验证 exp 的 remote 模式与本地模式走完全相同的利用链（只换传输层）。
"""
import os
import socket
import subprocess
import threading

HOST, PORT = "0.0.0.0", 9999


def sock_to_proc(conn, proc):
    """客户端 -> vuln2 的 stdin"""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            proc.stdin.write(data)
            proc.stdin.flush()
    except OSError:
        pass
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass


def proc_to_sock(proc, conn):
    """vuln2 的 stdout -> 客户端。用 os.read(fd) 而非 read(n)，
    避免管道缓冲攒满才转发，保证 "input> " 这类小输出实时到达。"""
    try:
        while True:
            data = os.read(proc.stdout.fileno(), 4096)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(conn):
    proc = subprocess.Popen(["./vuln2"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    t1 = threading.Thread(target=sock_to_proc, args=(conn, proc), daemon=True)
    t2 = threading.Thread(target=proc_to_sock, args=(proc, conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    proc.kill()
    conn.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print("[*] listening on %s:%d (one-shot)" % (HOST, PORT), flush=True)
    conn, addr = s.accept()
    print("[+] connection from %s" % (addr,), flush=True)
    handle(conn)


if __name__ == "__main__":
    main()