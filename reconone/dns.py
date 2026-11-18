"""Minimal DNS client (stdlib only): A/AAAA/CNAME/MX/NS/TXT/SOA plus resolver discovery.

No dnspython: the wire format is small enough to speak directly, which keeps the tool
copiable onto an operator host without a package index.
"""
from __future__ import annotations

import ipaddress
import os
import random
import socket
import struct
import sys
import time

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
QNAME = {v: k for k, v in QTYPE.items()}


class DNSError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(raw) > 63:
            raise DNSError(f"label too long: {label[:20]}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _build_query(name: str, qtype: int, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    ret = off
    hops = 0
    while True:
        if off >= len(buf):
            raise DNSError("truncated name")
        length = buf[off]
        if length == 0:
            off += 1
            if not jumped:
                ret = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise DNSError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                ret = off + 2
                jumped = True
            off = ptr
            hops += 1
            if hops > 64:
                raise DNSError("compression loop")
            continue
        off += 1
        labels.append(buf[off:off + length].decode("utf-8", "replace"))
        off += length
    return ".".join(labels), ret


def _parse(buf: bytes):
    if len(buf) < 12:
        raise DNSError("short packet")
    txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        _, off = _read_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        name, off = _read_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + rdlen]
        off += rdlen
        answers.append((name, rtype, ttl, rd))
    return txid, rcode, answers


def _rdata_text(rtype: int, rd: bytes) -> str:
    try:
        if rtype == 1 and len(rd) == 4:
            return socket.inet_ntoa(rd)
        if rtype == 28 and len(rd) == 16:
            return socket.inet_ntop(socket.AF_INET6, rd)
        if rtype in (2, 5):
            return _read_name(rd, 0)[0]
        if rtype == 15 and len(rd) > 3:
            pref = struct.unpack("!H", rd[:2])[0]
            return f"{pref} {_read_name(rd, 2)[0]}"
        if rtype == 16:
            chunks, i = [], 0
            while i < len(rd):
                n = rd[i]
                chunks.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            return "".join(chunks)
        if rtype == 6:
            mname, off = _read_name(rd, 0)
            rname, off = _read_name(rd, off)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", rd[off:off + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    except (DNSError, struct.error, OSError):
        return ""
    return rd.hex()


def _addr_matches(addr, server: str, port: int | None = None) -> bool:
    """True when `addr` (as returned by recvfrom) is the resolver we asked.

    Both parts matter: a reply carrying the right IP but a different source port comes from
    another process on that host, not from the resolver we queried.
    """
    host = addr[0] if isinstance(addr, tuple) else str(addr)
    peer_port = addr[1] if isinstance(addr, tuple) and len(addr) > 1 else None
    if port is not None and peer_port is not None and peer_port != port:
        return False
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(server)
    except ValueError:
        return host == server


def _udp(server: str, packet: bytes, timeout: float, txid: int, port: int = 53) -> bytes:
    """Send one query and accept only a reply from *that* server carrying *our* txid.

    Accepting the first datagram that arrives (the previous behaviour) is the classic
    off-path poisoning primitive: any source address and any transaction id counted as the
    answer. Source IP:port, transaction id and the QR bit are all checked here.
    """
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    deadline = time.time() + timeout
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.sendto(packet, (server, port))
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout("no matching reply before deadline")
            s.settimeout(left)
            data, addr = s.recvfrom(4096)
            if not _addr_matches(addr, server, port):
                continue                      # spoofed or unsolicited source
            if len(data) < 12:
                continue
            if struct.unpack("!H", data[:2])[0] != txid:
                continue                      # someone else's transaction
            if not struct.unpack("!H", data[2:4])[0] & 0x8000:
                continue                      # not a response
            return data


def _tcp(server: str, packet: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 53))
        s.sendall(struct.pack("!H", len(packet)) + packet)
        head = s.recv(2)
        if len(head) < 2:
            raise DNSError("short tcp length")
        need = struct.unpack("!H", head)[0]
        buf = b""
        while len(buf) < need:
            chunk = s.recv(need - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf


def query(name: str, qtype: str, servers: list[str], timeout: float = 3.0) -> list[str]:
    """Return answer strings for one record type, trying each resolver in order."""
    code = QTYPE.get(qtype.upper())
    if code is None:
        raise DNSError(f"unsupported type {qtype}")
    last = None
    for server in servers:
        txid = random.randint(0, 0xFFFF)
        packet = _build_query(name, code, txid)
        try:
            raw = _udp(server, packet, timeout, txid)
            _tid, rcode, answers = _parse(raw)
            # truncated flag -> retry over TCP, same transaction id
            if struct.unpack("!H", raw[2:4])[0] & 0x0200:
                raw = _tcp(server, packet, timeout)
                _tid, rcode, answers = _parse(raw)
                if _tid != txid:
                    raise DNSError(f"transaction id mismatch over TCP from {server}")
            if rcode not in (0, 3):
                raise DNSError(f"rcode {rcode} from {server}")
            return [t for t in (_rdata_text(t, rd) for (_n, t, _ttl, rd) in answers) if t]
        except (socket.timeout, OSError, DNSError) as exc:
            last = exc
            continue
    raise DNSError(f"all resolvers failed for {name}/{qtype}: {last}")


def system_resolvers() -> list[str]:
    override = os.environ.get("RECONONE_DNS", "").strip()
    if override:
        return [s.strip() for s in override.split(",") if s.strip()]
    found: list[str] = []
    if sys.platform.startswith("win"):
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
                i = 0
                while True:
                    try:
                        iface = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, iface) as key:
                            val, _ = winreg.QueryValueEx(key, "NameServer")
                            found += [v.strip() for v in str(val).split(",") if v.strip()]
                    except OSError:
                        continue
        except (ImportError, OSError):
            pass
    else:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1:
                            found.append(parts[1])
        except OSError:
            pass
    seen, out = set(), []
    for s in found:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out or ["1.1.1.1", "8.8.8.8"]


def dns_probe(domain: str, timeout: float = 3.0, types: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")) -> dict:
    servers = system_resolvers()
    records: dict[str, list[str]] = {}
    errors: list[dict] = []
    for qtype in types:
        try:
            records[qtype] = sorted(set(query(domain, qtype, servers, timeout)))
        except DNSError as exc:
            records[qtype] = []
            errors.append({"type": qtype, "error": str(exc)[:200]})
    txt = records.get("TXT", [])
    dmarc: list[str] = []
    for record in txt:
        if record.lower().startswith("v=dmarc1"):
            dmarc.append(record)
    try:
        dmarc = sorted(set(query(f"_dmarc.{domain}", "TXT", servers, timeout)))
    except DNSError:
        pass
    return {
        "domain": domain,
        "resolvers": servers,
        "records": records,
        "dmarc": dmarc,
        "spf": [r for r in txt if r.lower().startswith("v=spf1")],
        "errors": errors,
    }
