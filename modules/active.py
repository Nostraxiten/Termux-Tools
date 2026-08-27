# -*- coding: utf-8 -*-
"""Modulo de Escaneo Activo / Agresivo. TCP connect scan (sin root)."""
import os
import sys
import re
import ipaddress
import urllib.parse
import concurrent.futures as cf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ui, net
from core import banner as B

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
             465, 587, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083, 2222,
             3000, 3306, 3389, 4444, 5000, 5432, 5900, 5985, 6379, 7001, 8000,
             8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 11211, 27017]

COMMON_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elastic", 11211: "memcached", 27017: "mongodb",
}

DEFAULT_DIRS = [
    "admin", "login", "dashboard", "wp-admin", "wp-login.php", "administrator",
    "phpmyadmin", "robots.txt", "sitemap.xml", "backup", "backups", "old", "test",
    "dev", "api", "api/v1", "config", "config.php", ".git/config", ".env", "uploads",
    "images", "css", "js", "includes", "tmp", "logs", "log", "db", "database", "sql",
    "assets", "private", "secret", "panel", "cpanel", "webmail", "mail",
    "server-status", "phpinfo.php", "info.php", "readme.txt", "README.md",
    "CHANGELOG.txt", "debug", "status", "health", "metrics", "actuator", "swagger",
    "docs", ".htaccess", "wp-config.php.bak", "backup.zip", "db.sql",
]

DEFAULT_SUBS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "dns", "mx", "api", "api2", "dev", "development", "staging", "stage", "test",
    "qa", "uat", "admin", "portal", "vpn", "remote", "cpanel", "whm", "autodiscover",
    "autoconfig", "m", "mobile", "blog", "shop", "store", "cdn", "static", "assets",
    "img", "images", "media", "git", "gitlab", "svn", "jenkins", "ci", "docs", "wiki",
    "support", "help", "status", "monitor", "grafana", "kibana", "elastic", "db",
    "sql", "mysql", "phpmyadmin", "pma", "backup", "old", "new", "beta", "secure",
    "login", "auth", "sso", "proxy", "gw", "gateway", "internal", "intranet", "app",
    "apps", "cloud", "s3", "email", "news", "forum", "chat", "video", "stream",
]


def _load_wordlist(fname, fallback):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", fname)
    try:
        with open(path, encoding="utf-8") as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return words or fallback
    except Exception:
        return fallback


def _scan_ports(host, ports, timeout=1.0, workers=100):
    open_ports = []

    def one(p):
        return p if net.tcp_connect(host, p, timeout) else None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, ports):
            if r:
                open_ports.append(r)
    return sorted(open_ports)


def quick_scan():
    ui.banner_line("Escaneo rapido  (top ~50 puertos, TCP connect)")
    host = ui.ask("Host/IP:")
    if not host:
        return
    ip = net.resolve(host)
    if not ip:
        ui.bad("No resuelve"); return
    ui.info(f"{host} -> {ip}  escaneando...")
    op = _scan_ports(ip, sorted(set(TOP_PORTS)), timeout=1.0)
    if not op:
        ui.warn("Sin puertos abiertos (o filtrados)."); return
    for p in op:
        ui.good(f"{p:<6} {COMMON_NAMES.get(p, '?')}")


def port_scan():
    ui.banner_line("Escaneo de rango de puertos")
    host = ui.ask("Host/IP:")
    if not host:
        return
    rng = ui.ask("Rango (ej 1-1024) [enter=1-1024]:") or "1-1024"
    try:
        a, b = rng.split("-"); ports = list(range(int(a), int(b) + 1))
    except Exception:
        ui.bad("Rango invalido"); return
    ip = net.resolve(host)
    if not ip:
        ui.bad("No resuelve"); return
    ui.info(f"{host} -> {ip}  puertos {rng}  ({len(ports)} puertos, puede tardar)...")
    op = _scan_ports(ip, ports, timeout=0.8, workers=200)
    if not op:
        ui.warn("Sin puertos abiertos."); return
    for p in op:
        ui.good(f"{p:<6} {COMMON_NAMES.get(p, '?')}")
    ui.item("Total abiertos", len(op))


def banner_grab():
    ui.banner_line("Banner Grabbing")
    host = ui.ask("Host/IP:")
    if not host:
        return
    ports_s = ui.ask("Puertos coma [enter=comunes]:")
    ports = ([int(x) for x in ports_s.split(",") if x.strip().isdigit()]
             if ports_s else [21, 22, 25, 80, 110, 143, 443, 3306, 8080])
    ip = net.resolve(host) or host
    any_open = False
    for p in ports:
        if not net.tcp_connect(ip, p, 1.0):
            continue
        any_open = True
        b = net.grab_banner(ip, p, 2.5)
        ui.good(f"Puerto {p} ({COMMON_NAMES.get(p, '?')}):")
        shown = b.replace("\n", "\n     ") if b else "(sin banner)"
        print(B.GREY + "     " + shown + B.RESET)
    if not any_open:
        ui.warn("Ningun puerto abierto de los indicados.")


def host_sweep():
    ui.banner_line("Barrido de red  (TCP ping sweep, sin root)")
    net_s = ui.ask("Red CIDR (ej 192.168.1.0/24):")
    if not net_s:
        return
    try:
        network = ipaddress.ip_network(net_s, strict=False)
    except Exception as e:
        ui.bad(f"CIDR invalido: {e}"); return
    hosts = list(network.hosts())
    if len(hosts) > 512:
        ui.warn(f"{len(hosts)} hosts; limitando a 512."); hosts = hosts[:512]
    probe_ports = [80, 443, 22, 445, 3389]
    ui.info(f"Sondeando {len(hosts)} hosts en puertos {probe_ports}...")

    def alive(ip):
        ip = str(ip)
        for p in probe_ports:
            if net.tcp_connect(ip, p, 0.6):
                return (ip, p)
        return None

    live = []
    with cf.ThreadPoolExecutor(max_workers=100) as ex:
        for r in ex.map(alive, hosts):
            if r:
                live.append(r); ui.good(f"{r[0]:<16} activo (puerto {r[1]} abierto)")
    ui.item("Hosts vivos", len(live))
    if not live:
        ui.warn("Ninguno respondio (pueden estar filtrados).")


def dir_brute():
    ui.banner_line("Directory Bruteforce  (web)")
    url = ui.ask("URL base (ej http://host):")
    if not url:
        return
    base = (url if "://" in url else "http://" + url).rstrip("/")
    wl = _load_wordlist("dirs.txt", DEFAULT_DIRS)
    ui.info(f"Probando {len(wl)} rutas en {base} ...")

    def check(path):
        u = f"{base}/{path}"
        code, _h, body, _f = net.http_request(u, method="GET", timeout=6)
        if code and code != 404:
            return (code, u, len(body))
        return None

    hits = 0
    with cf.ThreadPoolExecutor(max_workers=30) as ex:
        for r in ex.map(check, wl):
            if r:
                code, u, ln = r
                col = B.GREEN if code < 400 else (B.AMBER if code < 500 else B.RED)
                print(f"   {col}[{code}]{B.RESET} {u}  {B.GREY}({ln}b){B.RESET}"); hits += 1
    if not hits:
        ui.warn("Sin resultados relevantes.")


def subdomain_brute():
    ui.banner_line("Subdomain Bruteforce  (resolucion activa)")
    d = ui.ask("Dominio:")
    if not d:
        return
    wl = _load_wordlist("subdomains.txt", DEFAULT_SUBS)
    ui.info(f"Resolviendo {len(wl)} candidatos para {d} ...")

    def resolve_sub(h):
        fqdn = f"{h}.{d}"
        recs = net.dns_query(fqdn, "A")
        if recs:
            return (fqdn, ",".join(r["value"] for r in recs))
        return None

    found = 0
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(resolve_sub, wl):
            if r:
                ui.good(f"{r[0]:<32} {r[1]}"); found += 1
    ui.item("Encontrados", found)


def http_methods():
    ui.banner_line("HTTP Methods  (verbos permitidos)")
    url = ui.ask("URL:")
    if not url:
        return
    code, hdrs, _b, _f = net.http_request(url, method="OPTIONS", timeout=10)
    allow = None
    for k, v in hdrs.items():
        if k.lower() == "allow":
            allow = v
    if allow:
        ui.good(f"Allow: {allow}")
    else:
        ui.warn("Sin cabecera Allow; probando verbos manualmente...")
    for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "HEAD"):
        c, _h, _b, _f = net.http_request(url, method=m, timeout=8)
        mark = B.GREEN if (c and c < 400) else B.GREY
        print(f"   {mark}{m:<7}{B.RESET} -> {c}")


def web_crawler():
    ui.banner_line("Web Crawler  (enlaces internos + formularios)")
    url = ui.ask("URL inicial:")
    if not url:
        return
    start = url if "://" in url else "http://" + url
    dom = urllib.parse.urlparse(start).netloc
    code, _h, body, _f = net.http_request(start, timeout=12)
    if code is None:
        ui.bad("No responde"); return
    txt = body.decode("utf-8", "replace")
    links = set()
    for m in re.findall(r'href=["\']([^"\']+)["\']', txt, re.I):
        full = urllib.parse.urljoin(start, m)
        if urllib.parse.urlparse(full).netloc == dom:
            links.add(full.split("#")[0])
    ui.good(f"{len(links)} enlaces internos:")
    for l in sorted(links)[:40]:
        print(f"     {B.ORANGE}{l}{B.RESET}")
    forms = re.findall(r"<form[^>]*>", txt, re.I)
    if forms:
        ui.info(f"{len(forms)} formularios detectados:")
        for fform in forms[:8]:
            print(f"     {B.GREY}{fform[:120]}{B.RESET}")


def vhost_scan():
    ui.banner_line("VHost Scan  (fuzzing de cabecera Host)")
    ip = ui.ask("IP del servidor:")
    if not ip:
        return
    base_domain = ui.ask("Dominio base (ej example.com):")
    if not base_domain:
        return
    wl = _load_wordlist("subdomains.txt", DEFAULT_SUBS)
    ui.info("Comparando respuestas por cabecera Host...")
    _c, _h, b0, _f = net.http_request(
        f"http://{ip}/", headers={"Host": "no-existe-baseline.invalid"}, timeout=8)
    base_len = len(b0)

    def probe(sub):
        host = f"{sub}.{base_domain}"
        c, _h, b, _f = net.http_request(f"http://{ip}/", headers={"Host": host}, timeout=8)
        if c and abs(len(b) - base_len) > 60:
            return (host, c, len(b))
        return None

    hits = 0
    with cf.ThreadPoolExecutor(max_workers=25) as ex:
        for r in ex.map(probe, wl):
            if r:
                ui.good(f"{r[0]:<30} [{r[1]}] {r[2]}b (baseline {base_len}b)"); hits += 1
    if not hits:
        ui.warn("Sin vhosts diferenciables.")


def service_detect():
    ui.banner_line("Deteccion de servicios  (scan + banner)")
    host = ui.ask("Host/IP:")
    if not host:
        return
    ip = net.resolve(host)
    if not ip:
        ui.bad("No resuelve"); return
    ui.info(f"{host} -> {ip}  identificando servicios...")
    op = _scan_ports(ip, sorted(set(TOP_PORTS)), timeout=1.0)
    if not op:
        ui.warn("Sin puertos abiertos."); return
    for p in op:
        b = net.grab_banner(ip, p, 2.0)
        version = ""
        if b:
            first = b.splitlines()[0] if b.splitlines() else b
            version = first[:80]
        ui.good(f"{p:<6} {COMMON_NAMES.get(p, '?'):<10} {B.GREY}{version}{B.RESET}")


TOOLS = [
    ("1", "Escaneo rapido (top ports)", quick_scan),
    ("2", "Escaneo de rango de puertos", port_scan),
    ("3", "Banner grabbing", banner_grab),
    ("4", "Barrido de red (host sweep)", host_sweep),
    ("5", "Directory bruteforce", dir_brute),
    ("6", "Subdomain bruteforce", subdomain_brute),
    ("7", "HTTP methods", http_methods),
    ("8", "Web crawler", web_crawler),
    ("9", "VHost scan", vhost_scan),
    ("10", "Deteccion de servicios", service_detect),
]


def menu():
    while True:
        ui.clear()
        ui.menu("ESCANEO ACTIVO / AGRESIVO", [(k, l) for k, l, _ in TOOLS])
        ui.warn("Usa esto SOLO en sistemas propios o con permiso.")
        ui.rule()
        ch = ui.ask("Opcion:")
        if ch in ("0", ""):
            return
        for k, _l, fn in TOOLS:
            if ch == k:
                try:
                    fn()
                except KeyboardInterrupt:
                    print()
                except Exception as e:
                    ui.bad(f"Error: {e}")
                ui.pause()
                break
        else:
            ui.warn("Opcion invalida"); ui.pause()


if __name__ == "__main__":
    menu()
