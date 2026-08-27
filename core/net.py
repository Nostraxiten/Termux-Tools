# -*- coding: utf-8 -*-
"""
Helpers de red 100% stdlib. Nada de nmap/whois/dig: los protocolos
(DNS, WHOIS, TCP, TLS, HTTP) se hablan a mano con sockets y urllib.
"""
import socket
import ssl
import struct
import random
import json
import urllib.request
import urllib.error
import urllib.parse
from email.message import Message

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) TermuxTool/1.0 (+github.com/nostraxiten)"
DNS_SERVER = "1.1.1.1"


# ============================================================ HTTP
def http_request(url, method="GET", headers=None, timeout=12, data=None):
    """
    Devuelve (status:int|None, headers:HTTPMessage, body:bytes, final_url:str).
    Los headers son un objeto tipo email.Message: soporta hdrs[k], k in hdrs,
    hdrs.items() y hdrs.get_all('Set-Cookie') (mantiene duplicados).
    """
    if "://" not in url:
        url = "http://" + url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, method=method, headers=hdrs, data=data)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.getcode(), resp.headers, resp.read(), resp.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, (e.headers or Message()), body, url
    except Exception as e:
        return None, Message(), str(e).encode(), url


def http_json(url, timeout=12, headers=None):
    """Devuelve (obj|None, error|None)."""
    code, _hdrs, body, _final = http_request(url, headers=headers, timeout=timeout)
    if code is None:
        return None, body.decode("utf-8", "replace")
    try:
        return json.loads(body.decode("utf-8", "replace")), None
    except Exception as e:
        return None, f"JSON parse error: {e}"


# ============================================================ DNS propio (UDP)
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
          "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
RQTYPES = {v: k for k, v in QTYPES.items()}


def _dns_encode(name):
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _dns_read_name(data, offset):
    """Lee un nombre DNS resolviendo punteros de compresion (0xC0)."""
    labels, jumped, start, hops = [], False, offset, 0
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:                 # puntero de compresion
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                start = offset + 2
            offset, jumped, hops = ptr, True, hops + 1
            if hops > 20:
                break
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (start if jumped else offset)


def _dns_udp(packet, server, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(4096)
        return data
    except Exception:
        return b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _dns_tcp(packet, server, timeout):
    """DNS-over-TCP (prefijo de 2 bytes con la longitud). Para respuestas grandes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, 53))
        s.sendall(struct.pack(">H", len(packet)) + packet)
        hdr = b""
        while len(hdr) < 2:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                return b""
            hdr += chunk
        (length,) = struct.unpack(">H", hdr)
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data
    except Exception:
        return b""
    finally:
        try:
            s.close()
        except Exception:
            pass


def _dns_parse(data):
    """Parsea una respuesta DNS cruda -> lista de dicts {type,ttl,value}."""
    results = []
    if len(data) < 12:
        return results
    _, _flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):                             # saltar seccion de pregunta
        _, off = _dns_read_name(data, off)
        off += 4
    for _ in range(an):                             # respuestas
        _rname, off = _dns_read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        results.append({"type": RQTYPES.get(rtype, str(rtype)),
                        "ttl": ttl,
                        "value": _parse_rdata(rtype, rdata, data, off)})
        off += rdlen
    return results


def dns_query(name, qtype="A", server=DNS_SERVER, timeout=5):
    """
    Consulta DNS cruda. Intenta UDP y, si la respuesta viene truncada
    (bit TC), reintenta por TCP. Devuelve lista de dicts {type,ttl,value}.
    """
    qt = QTYPES.get(qtype.upper(), 1)
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # recursion desired
    packet = header + _dns_encode(name) + struct.pack(">HH", qt, 1)

    data = _dns_udp(packet, server, timeout)
    if len(data) >= 12:
        flags = struct.unpack(">H", data[2:4])[0]
        truncated = bool(flags & 0x0200)            # bit TC
        if truncated:
            tcp_data = _dns_tcp(packet, server, timeout)
            if len(tcp_data) >= 12:
                data = tcp_data
    return _dns_parse(data)


def _parse_rdata(rtype, rdata, full, off):
    try:
        if rtype == 1 and len(rdata) == 4:                       # A
            return ".".join(str(b) for b in rdata)
        if rtype == 28 and len(rdata) == 16:                     # AAAA
            return ":".join(f"{(rdata[i] << 8) | rdata[i + 1]:x}" for i in range(0, 16, 2))
        if rtype in (2, 5, 12):                                  # NS / CNAME / PTR
            n, _ = _dns_read_name(full, off)
            return n
        if rtype == 15:                                          # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            n, _ = _dns_read_name(full, off + 2)
            return f"{pref} {n}"
        if rtype == 16:                                          # TXT
            out, i = [], 0
            while i < len(rdata):
                l = rdata[i]; i += 1
                out.append(rdata[i:i + l].decode("utf-8", "replace")); i += l
            return " | ".join(out)
        if rtype == 6:                                           # SOA
            mname, o = _dns_read_name(full, off)
            rname, _ = _dns_read_name(full, o)
            return f"{mname} {rname}"
    except Exception:
        pass
    return rdata.hex()


# ============================================================ WHOIS (puerto 43)
def whois_query(domain, timeout=10):
    """WHOIS recursivo: pregunta a IANA por el servidor autoritativo y reconsulta."""
    domain = domain.strip().lower()

    def _q(server, query):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((server, 43))
            s.sendall((query + "\r\n").encode())
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 200000:
                    break
            s.close()
            return buf.decode("utf-8", "replace")
        except Exception as e:
            return f"__ERR__ {e}"

    iana = _q("whois.iana.org", domain)
    refer = None
    for line in iana.splitlines():
        if line.lower().startswith("refer:"):
            refer = line.split(":", 1)[1].strip()
            break
    if refer:
        data = _q(refer, domain)
        if not data.startswith("__ERR__"):
            return f"[whois via {refer}]\n" + data
    return "[whois via whois.iana.org]\n" + iana


# ============================================================ Sockets / puertos
def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def tcp_connect(host, port, timeout=1.0):
    """TCP connect scan (SOCK_STREAM): no requiere root, funciona en Termux."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        r = s.connect_ex((host, port))
        return r == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def grab_banner(host, port, timeout=2.0, probe=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if probe:
            s.sendall(probe)
        elif port in (80, 8080, 8000, 8888, 8081):
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = s.recv(2048)
        s.close()
        return data.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def get_public_ip():
    for url in ("https://api.ipify.org?format=json", "http://ip-api.com/json/"):
        j, _err = http_json(url, timeout=8)
        if j:
            return j.get("ip") or j.get("query")
    return None
