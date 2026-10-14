#!/usr/bin/env python3
"""A small ONC RPC portmapper (rpcbind) used to verify the rpcbind template.

It speaks the portmap v2 (RFC 1057) and RPCB v3 (RFC 1833) wire formats over
TCP (with ONC record marking) and UDP. It is deliberately strict, because the
template's rules are written against the bytes a real rpcbind puts on the wire:

  * a v2 registry entry is  prog, vers, prot, port   (all four byte words)
  * a v3 registry entry is  prog, vers, netid, uaddr, owner (three XDR strings)
  * the registry is an XDR linked list, so every entry is preceded by a
    four byte "more entries follow" marker and the list ends with a zero
  * a TCP call is prefixed with a four byte record marker, UDP is not
  * a malformed datagram or an unparsable call is dropped *silently*, which is
    what rpcbind does: it never answers something it could not decode
  * an unsupported *version* is answered PROG_MISMATCH with the supported
    range, an unsupported *program* is answered PROG_UNAVAIL

Those last two points matter: they are what keeps a fingerprint pattern honest.
A pattern that only looks for a successful reply must not fire on a mismatch.

Everything this server does is logged line by line, so the verification script
can assert on the wire traffic as well as on argus's report.

Usage:
    python fake-rpcbind.py --profile modern --tcp-port 111 --udp-port 111
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time

MAX_RECORD = 1 << 20

# XDR primitives. Everything in ONC RPC is four byte aligned, big endian.


def u32(n: int) -> bytes:
    return struct.pack(">I", n & 0xFFFFFFFF)


def xdr_str(s: str) -> bytes:
    b = s.encode("utf-8", "replace")
    pad = (4 - len(b) % 4) % 4
    return u32(len(b)) + b + b"\x00" * pad


def universal_address(host: str, port: int) -> str:
    """RFC 1833 universal address: dotted host, then the port as two bytes."""
    return f"{host}.{port // 256}.{port % 256}"


# RPC constants.
CALL, REPLY = 0, 1
MSG_ACCEPTED = 0
SUCCESS, PROG_UNAVAIL, PROG_MISMATCH, PROC_UNAVAIL = 0, 1, 2, 3
RPCB_PROG = 100000

# Procedure numbers per protocol version (RFC 1057 / RFC 1833).
PROC_NULL = 0
PROC_GETPORT = 3  # v2 only: portmap GETPORT
PROC_GETADDR = 3  # v3/v4: rpcbind GETADDR
PROC_DUMP = 4  # all versions

# /etc/rpc, for readable logs and for the registry the "modern" profile serves.
PROGRAM_NAMES = {
    100000: "portmapper/rpcbind",
    100001: "rstatd",
    100002: "rusersd",
    100003: "nfs",
    100004: "ypserv",
    100005: "mountd",
    100008: "walld",
    100011: "rquotad",
    100012: "sprayd",
    100017: "rexd",
    100021: "nlockmgr",
    100024: "status",
    100026: "bootparam",
    100029: "keyserv",
    100227: "nfs_acl",
    300019: "amd/amq",
}

PROT_NAMES = {6: "tcp", 17: "udp"}


class Registry:
    """The mappings this portmapper advertises."""

    def __init__(self, entries, supports_v3: bool):
        # entries: (prog, vers, netid, port, owner)
        self.entries = entries
        self.supports_v3 = supports_v3

    def versions(self):
        return sorted({v for _, v, _, _, _ in self.entries})

    def protocol_versions(self):
        """The rpcbind *protocol* versions on offer.

        Not the same thing as the versions in the registry: those belong to the
        registered programs. The protocol versions are the ones program 100000
        itself is registered under, which is what a caller asks for in the
        "vers" field of a call.
        """
        return sorted({v for p, v, _, _, _ in self.entries if p == RPCB_PROG})

    def lookup(self, prog: int, vers: int, netid: str):
        for p, v, n, port, _owner in self.entries:
            if p == prog and v == vers and n == netid:
                return port
        return None


def registry_for(profile: str) -> Registry:
    # A modern rpcbind registers itself first: v2 and v3 over tcp and udp, plus
    # v4 over tcp. That is why a DUMP answer starts with program 100000.
    self_registered = [
        (100000, 2, "tcp", 111, "superuser"),
        (100000, 2, "udp", 111, "superuser"),
        (100000, 3, "tcp", 111, "superuser"),
        (100000, 3, "udp", 111, "superuser"),
        (100000, 4, "tcp", 111, "superuser"),
    ]

    if profile == "modern":
        return Registry(
            self_registered
            + [
                # The NFS family.
                (100003, 3, "tcp", 2049, "superuser"),
                (100003, 3, "udp", 2049, "superuser"),
                (100227, 1, "tcp", 2049, "superuser"),
                (100005, 3, "tcp", 20048, "superuser"),
                (100005, 3, "udp", 20048, "superuser"),
                (100021, 4, "tcp", 35303, "superuser"),
                (100024, 1, "tcp", 38397, "superuser"),
                (100011, 1, "tcp", 875, "superuser"),
                # The legacy SunOS-era daemons this template reports on. They
                # are the reason a DUMP answer is worth reading in full.
                (100001, 2, "udp", 32777, "superuser"),  # rstatd
                (100002, 2, "udp", 32778, "superuser"),  # rusersd
                (100008, 1, "udp", 32779, "superuser"),  # walld
                (100012, 1, "udp", 32780, "superuser"),  # sprayd
                (100017, 1, "udp", 32781, "superuser"),  # rexd
                (100026, 1, "udp", 32782, "superuser"),  # bootparam
                (100029, 1, "udp", 32783, "superuser"),  # keyserv
                (300019, 1, "udp", 32784, "superuser"),  # amd/amq
            ],
            supports_v3=True,
        )

    if profile == "v2only":
        # An old portmap: version 2 only, so a v3 call is answered with
        # PROG_MISMATCH and the supported range.
        return Registry(
            [
                (100000, 2, "tcp", 111, "superuser"),
                (100000, 2, "udp", 111, "superuser"),
                (100003, 2, "tcp", 2049, "superuser"),
            ],
            supports_v3=False,
        )

    if profile == "rexd-last":
        # A registry where the program under test is the *last* entry of the
        # list, which is the case a "more entries follow" pattern with a fixed
        # value of 1 silently misses.
        return Registry(
            [
                (100000, 2, "tcp", 111, "superuser"),
                (100000, 2, "udp", 111, "superuser"),
                (100017, 1, "udp", 32781, "superuser"),
            ],
            supports_v3=False,
        )

    raise SystemExit(f"unknown profile {profile!r}")


class Server:
    def __init__(self, registry: Registry, args):
        self.reg = registry
        self.args = args
        self.lock = threading.Lock()
        self.log_lock = threading.Lock()

    def log(self, fmt, *a):
        with self.log_lock:
            print(("[%s] " % time.strftime("%H:%M:%S")) + (fmt % a), flush=True)

    # ---------------------------------------------------------------- replies

    def reply_header(self, xid: int, accept_stat: int) -> bytes:
        # xid, REPLY, MSG_ACCEPTED, verifier AUTH_NULL + length 0, accept_stat.
        return u32(xid) + u32(REPLY) + u32(MSG_ACCEPTED) + u32(0) + u32(0) + u32(accept_stat)

    def v2_dump_body(self) -> bytes:
        out = b""
        for prog, vers, netid, port, _owner in self.reg.entries:
            if netid not in ("tcp", "udp"):
                continue
            prot = 6 if netid == "tcp" else 17
            out += u32(1) + u32(prog) + u32(vers) + u32(prot) + u32(port)
        return out + u32(0)

    def v3_dump_body(self) -> bytes:
        out = b""
        for prog, vers, netid, port, owner in self.reg.entries:
            out += u32(1) + u32(prog) + u32(vers)
            out += xdr_str(netid)
            out += xdr_str(universal_address(self.args.uaddr_host, port))
            out += xdr_str(owner)
        return out + u32(0)

    def handle_call(self, body: bytes, transport: str):
        """Return the reply bytes for one call body, or None for silence."""
        if len(body) < 40:
            self.log("%s dropped: call body is %d bytes, too short to decode", transport, len(body))
            return None
        (
            xid,
            msg_type,
            rpcvers,
            prog,
            vers,
            proc,
            cred_flavor,
            cred_len,
        ) = struct.unpack(">IIIIIIII", body[:32])
        cred_len = struct.unpack(">I", body[28:32])[0]
        # credential body, then the verifier
        off = 32 + cred_len
        if off + 8 > len(body):
            self.log("%s dropped: credential length %d does not fit", transport, cred_len)
            return None
        verf_flavor, verf_len = struct.unpack(">II", body[off : off + 8])
        args_off = off + 8 + verf_len

        name = PROGRAM_NAMES.get(prog, "program %d" % prog)
        if msg_type != CALL:
            self.log("%s dropped: msg_type %d is not a CALL", transport, msg_type)
            return None

        self.log(
            "%s call xid=%d rpcvers=%d prog=%d (%s) vers=%d proc=%d cred=(%d,%d) verf=(%d,%d) body=%d bytes",
            transport, xid, rpcvers, prog, name, vers, proc,
            cred_flavor, cred_len, verf_flavor, verf_len, len(body),
        )
        if len(body) > args_off:
            self.log(
                "%s note: %d bytes follow the call (%s) - a real rpcbind reads the "
                "record length it was given and leaves the rest in the socket",
                transport, len(body) - args_off, body[args_off:].hex(),
            )

        if prog != RPCB_PROG:
            return self.reply_header(xid, PROG_UNAVAIL)
        # The field that selects the rpcbind protocol version is `vers` (the
        # version of program 100000), not `rpcvers`: ONC RPC itself is version 2
        # in every one of these calls, which is exactly the trap this comment
        # exists for.
        offered = self.reg.protocol_versions()
        if vers not in offered or (vers != 2 and not self.reg.supports_v3):
            lo, hi = min(offered), max(offered)
            self.log("%s -> PROG_MISMATCH for vers=%d (offers %d..%d)", transport, vers, lo, hi)
            return self.reply_header(xid, PROG_MISMATCH) + u32(lo) + u32(hi)

        if proc == PROC_NULL:
            return self.reply_header(xid, SUCCESS)
        if proc == PROC_DUMP:
            body_out = self.v2_dump_body() if vers == 2 else self.v3_dump_body()
            return self.reply_header(xid, SUCCESS) + body_out
        if vers == 2 and proc == PROC_GETPORT:
            # args: prog, vers, prot, port(ignored)
            p, v, prot = struct.unpack(">III", body[args_off : args_off + 12])
            port = self.reg.lookup(p, v, PROT_NAMES.get(prot, "tcp")) or 0
            return self.reply_header(xid, SUCCESS) + u32(port)
        if vers == 3 and proc == PROC_GETADDR:
            # args: prog, vers, netid, addr, owner. RFC 1833: GETADDR ignores
            # the netid in the argument and uses the transport it arrived on.
            p, v = struct.unpack(">II", body[args_off : args_off + 8])
            netid = "udp" if transport == "udp" else "tcp"
            port = self.reg.lookup(p, v, netid)
            addr = universal_address(self.args.uaddr_host, port) if port else ""
            return self.reply_header(xid, SUCCESS) + xdr_str(addr)

        self.log("%s -> PROC_UNAVAIL", transport)
        return self.reply_header(xid, PROC_UNAVAIL)

    # ------------------------------------------------------------- transports

    def tcp_handler(self, conn: socket.socket, addr):
        with self.lock:
            pass
        calls = 0
        try:
            while True:
                hdr = self.recv_exact(conn, 4)
                if not hdr:
                    if calls == 0:
                        self.log("tcp %s closed without sending anything (passive read)", addr[0])
                    return
                length = struct.unpack(">I", hdr)[0]
                last = bool(length & 0x80000000)
                length &= 0x7FFFFFFF
                if length > MAX_RECORD:
                    self.log("tcp %s: record marker claims %d bytes, dropping", addr[0], length)
                    return
                body = self.recv_exact(conn, length)
                if body is None:
                    self.log("tcp %s: connection closed mid-record", addr[0])
                    return
                calls += 1
                self.log(
                    "tcp %s: record marker=%s length=%d, %d byte call",
                    addr[0], "last-fragment" if last else "more-fragments", length, len(body),
                )
                reply = self.handle_call(body, "tcp")
                if reply is None:
                    return
                conn.sendall(u32(0x80000000 | len(reply)) + reply)
                self.log("tcp %s: reply %d bytes", addr[0], len(reply))
                if not last:
                    self.log("tcp %s: the call declared more fragments; waiting for them", addr[0])
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as e:
            self.log("tcp %s: %s", addr[0], e)
        finally:
            conn.close()

    @staticmethod
    def recv_exact(conn: socket.socket, n: int):
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None if buf else b""
            buf += chunk
        return buf

    def serve_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.bind_host, self.args.tcp_port))
        s.listen(16)
        self.log("listening on tcp/%s:%d (profile %s)", self.args.bind_host, self.args.tcp_port, self.args.profile)
        while True:
            conn, addr = s.accept()
            conn.settimeout(3.0)
            threading.Thread(target=self.tcp_handler, args=(conn, addr), daemon=True).start()

    def serve_udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.bind_host, self.args.udp_port))
        self.log("listening on udp/%s:%d", self.args.bind_host, self.args.udp_port)
        while True:
            data, addr = s.recvfrom(65535)
            # A datagram that is not a decodable call is dropped without a word:
            # that is how rpcbind behaves. It is what makes a strict mock worth
            # having -- "the service is filtered" and "the service could not
            # decode what we sent" look identical from the outside.
            reply = self.handle_call(data, "udp")
            if reply is None:
                self.log("udp %s: %d byte datagram dropped (no reply)", addr[0], len(data))
                continue
            s.sendto(reply, addr)
            self.log("udp %s: reply %d bytes", addr[0], len(reply))


class HTTPServer:
    """A fixed HTTP banner, for the negative control."""

    BANNER = b"HTTP/1.1 200 OK\r\nServer: mock-http/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def __init__(self, args):
        self.args = args

    def log(self, fmt, *a):
        print(("[%s] " % time.strftime("%H:%M:%S")) + (fmt % a), flush=True)

    def serve(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.args.bind_host, self.args.tcp_port))
        s.listen(16)
        self.log("listening on tcp/%s:%d (profile http)", self.args.bind_host, self.args.tcp_port)
        while True:
            conn, addr = s.accept()
            try:
                conn.settimeout(3.0)
                request = conn.recv(4096)
                self.log("http %s: %d byte request", addr[0], len(request))
                if request:
                    conn.sendall(self.BANNER)
            except OSError as e:
                self.log("http %s: %s", addr[0], e)
            finally:
                conn.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", default="modern", choices=["modern", "v2only", "rexd-last", "http"])
    ap.add_argument("--bind-host", default="127.0.0.1")
    # A wildcard-bound rpcbind reports 0.0.0.0 in a universal address, which is
    # what the report then shows. Keep that separate from the bind address so
    # the mock can listen on loopback and still answer like the real thing.
    ap.add_argument("--uaddr-host", default="0.0.0.0")
    ap.add_argument("--tcp-port", type=int, default=111)
    ap.add_argument("--udp-port", type=int, default=111)
    args = ap.parse_args()

    if args.profile == "http":
        HTTPServer(args).serve()
        return

    server = Server(registry_for(args.profile), args)
    threading.Thread(target=server.serve_udp, daemon=True).start()
    try:
        server.serve_tcp()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
