# -*- coding: utf-8 -*-
"""Modulo de Escaneo Pasivo (sin tocar apenas al objetivo)."""
import os
import sys
import re
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ui, net
from core import banner as B


def dns_enum():
    ui.banner_line("DNS Enum  (records + hostnames comunes)")
    d = ui.ask("Dominio:")
    if not d:
        return
    for t in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        for r in net.dns_query(d, t):
            ui.item(r["type"], f"{r['value']} (ttl {r['ttl']})")
    ui.info("Probando hostnames comunes...")
    common = ["www", "mail", "ftp", "webmail", "ns1", "ns2", "smtp", "pop", "imap",
              "api", "dev", "staging", "test", "admin", "portal", "vpn", "cpanel",
              "autodiscover", "m", "blog", "shop", "cdn", "git", "gitlab", "docs", "status"]
    found = 0
    for h in common:
        recs = net.dns_query(f"{h}.{d}", "A")
        if recs:
            ui.good(f"{h}.{d} -> " + ", ".join(r["value"] for r in recs)); found += 1
    if not found:
        ui.warn("Sin subdominios comunes resueltos.")


def subdomain_crtsh():
    ui.banner_line("Subdominios pasivos  (crt.sh / CT logs)")
    d = ui.ask("Dominio:")
    if not d:
        return
    ui.info("Consultando transparencia de certificados...")
    j, err = net.http_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(d)}&output=json", timeout=25)
    if not isinstance(j, list):
        ui.bad(f"crt.sh sin respuesta util ({err})."); return
    subs = set()
    for row in j:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name.endswith(d):
                subs.add(name)
    if not subs:
        ui.warn("Nada encontrado."); return
    ui.good(f"{len(subs)} subdominios unicos:")
    for s in sorted(subs):
        print(f"     {B.ORANGE}{s}{B.RESET}")


def robots_sitemap():
    ui.banner_line("robots.txt & sitemap.xml")
    url = ui.ask("Host/URL base:")
    if not url:
        return
    base = (url if "://" in url else "http://" + url).rstrip("/")
    for path in ("/robots.txt", "/sitemap.xml"):
        code, _h, body, _f = net.http_request(base + path, timeout=10)
        print(f"\n{B.LORANGE}== {path}  [{code}] =={B.RESET}")
        if code and 200 <= code < 400:
            txt = body.decode("utf-8", "replace")
            print(B.GREY + txt[:2500] + ("\n...(recortado)" if len(txt) > 2500 else "") + B.RESET)
        else:
            ui.warn("No disponible")


def security_txt():
    ui.banner_line(".well-known/security.txt")
    url = ui.ask("Host:")
    if not url:
        return
    base = (url if "://" in url else "https://" + url).rstrip("/")
    for path in ("/.well-known/security.txt", "/security.txt"):
        code, _h, body, _f = net.http_request(base + path, timeout=10)
        if code == 200:
            ui.good(f"Encontrado en {path}")
            print(B.GREY + body.decode("utf-8", "replace")[:2000] + B.RESET)
            return
    ui.warn("Sin security.txt")


SEC_HEADERS = {
    "Strict-Transport-Security": "Fuerza HTTPS (HSTS)",
    "Content-Security-Policy": "Mitiga XSS/inyeccion",
    "X-Frame-Options": "Anti-clickjacking",
    "X-Content-Type-Options": "Anti MIME-sniffing",
    "Referrer-Policy": "Control de referrer",
    "Permissions-Policy": "Control de APIs del navegador",
    "Cross-Origin-Opener-Policy": "Aislamiento (COOP)",
}


def security_headers_audit():
    ui.banner_line("Auditoria de cabeceras de seguridad")
    url = ui.ask("URL:")
    if not url:
        return
    code, hdrs, _b, _f = net.http_request(url, timeout=12)
    if code is None:
        ui.bad("No responde"); return
    lower = {k.lower(): v for k, v in hdrs.items()}
    present = 0
    for h, desc in SEC_HEADERS.items():
        if h.lower() in lower:
            present += 1
            ui.good(f"{h}: {lower[h.lower()][:70]}")
        else:
            ui.bad(f"FALTA {h}  ({desc})")
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if h.lower() in lower:
            ui.warn(f"Revela info: {h}: {lower[h.lower()]}")
    score = int(present / len(SEC_HEADERS) * 100)
    grade = ("A" if score >= 85 else "B" if score >= 65 else
             "C" if score >= 45 else "D" if score >= 25 else "F")
    ui.item("Puntuacion", f"{present}/{len(SEC_HEADERS)}  ({score}%)  Nota: {grade}")


def cookie_analysis():
    ui.banner_line("Analisis de cookies")
    url = ui.ask("URL:")
    if not url:
        return
    code, hdrs, _b, _f = net.http_request(url, timeout=12)
    if code is None:
        ui.bad("No responde"); return
    cookies = hdrs.get_all("Set-Cookie") or []
    if not cookies:
        ui.warn("Sin cookies en la respuesta."); return
    for cstr in cookies:
        name = cstr.split("=", 1)[0]
        f = cstr.lower()
        ui.item("Cookie", name)
        print(f"        Secure   : {'SI' if 'secure' in f else 'NO'}")
        print(f"        HttpOnly : {'SI' if 'httponly' in f else 'NO'}")
        ss = ("Strict" if "samesite=strict" in f else
              "Lax" if "samesite=lax" in f else
              "None" if "samesite=none" in f else "no definido")
        print(f"        SameSite : {ss}")


def email_harvest():
    ui.banner_line("Email Harvester  (scrape de la pagina)")
    url = ui.ask("URL:")
    if not url:
        return
    code, _h, body, _f = net.http_request(url, timeout=12)
    if code is None:
        ui.bad("No responde"); return
    txt = body.decode("utf-8", "replace")
    emails = set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", txt))
    if not emails:
        ui.warn("Sin emails en el HTML."); return
    ui.good(f"{len(emails)} emails:")
    for e in sorted(emails):
        print(f"     {B.ORANGE}{e}{B.RESET}")


def cms_detect():
    ui.banner_line("Deteccion de CMS  (por rutas conocidas)")
    url = ui.ask("Host/URL:")
    if not url:
        return
    base = (url if "://" in url else "http://" + url).rstrip("/")
    probes = {
        "WordPress": ["/wp-login.php", "/wp-json/", "/wp-content/"],
        "Joomla": ["/administrator/", "/language/en-GB/en-GB.xml"],
        "Drupal": ["/core/CHANGELOG.txt", "/user/login"],
        "Magento": ["/static/version", "/rest/V1/"],
        "PrestaShop": ["/modules/", "/admin-dev/"],
        "phpMyAdmin": ["/phpmyadmin/", "/pma/"],
    }
    hits = []
    for cms, paths in probes.items():
        for p in paths:
            code, _h, _b, _f = net.http_request(base + p, timeout=8)
            if code and code in (200, 301, 302, 401, 403):
                ui.good(f"{cms}: {p} -> {code}"); hits.append(cms); break
    if not hits:
        ui.warn("Sin CMS evidente por rutas.")


def http_meta():
    ui.banner_line("Meta info del HTML  (generator, comentarios)")
    url = ui.ask("URL:")
    if not url:
        return
    code, _h, body, _f = net.http_request(url, timeout=12)
    if code is None:
        ui.bad("No responde"); return
    txt = body.decode("utf-8", "replace")
    gen = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', txt, re.I)
    if gen:
        ui.item("Generator", gen[0])
    metas = re.findall(
        r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)', txt, re.I)
    for name, content in metas[:12]:
        ui.item(name[:20], content[:80])
    comments = [c.strip() for c in re.findall(r"<!--(.*?)-->", txt, re.S)
                if c.strip() and len(c.strip()) < 200]
    if comments:
        ui.info("Comentarios HTML:")
        for cmt in comments[:8]:
            print(f"     {B.GREY}{cmt[:120]}{B.RESET}")


TOOLS = [
    ("1", "DNS Enum (records + hosts)", dns_enum),
    ("2", "Subdominios via crt.sh (CT)", subdomain_crtsh),
    ("3", "robots.txt & sitemap.xml", robots_sitemap),
    ("4", "security.txt", security_txt),
    ("5", "Auditoria headers seguridad", security_headers_audit),
    ("6", "Analisis de cookies", cookie_analysis),
    ("7", "Email harvester", email_harvest),
    ("8", "Deteccion de CMS", cms_detect),
    ("9", "Meta info HTML", http_meta),
]


def menu():
    while True:
        ui.clear()
        ui.menu("ESCANEO PASIVO", [(k, l) for k, l, _ in TOOLS])
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
