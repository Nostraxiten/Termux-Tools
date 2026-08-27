# -*- coding: utf-8 -*-
"""Modulo OSINT & Reconocimiento."""
import os
import sys
import re
import ssl
import socket
import urllib.parse
import concurrent.futures as cf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import ui, net
from core import banner as B


def ip_info():
    ui.banner_line("IP / Host Info  (ip-api.com)")
    target = ui.ask("IP o dominio:")
    if not target:
        return
    ip = net.resolve(target) or target
    j, err = net.http_json(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10)
    if not j:
        ui.bad(f"Sin datos ({err})"); return
    if j.get("status") != "success":
        ui.bad(j.get("message", "fallo")); return
    ui.item("IP", j.get("query"))
    ui.item("Pais", f"{j.get('country')} ({j.get('countryCode')})")
    ui.item("Region/Ciudad", f"{j.get('regionName')} / {j.get('city')} {j.get('zip')}")
    ui.item("Coords", f"{j.get('lat')}, {j.get('lon')}  [{j.get('timezone')}]")
    ui.item("ISP", j.get("isp"))
    ui.item("Org", j.get("org"))
    ui.item("AS", j.get("as"))
    ui.item("rDNS", j.get("reverse"))
    ui.item("Movil/Proxy/Host", f"{j.get('mobile')} / {j.get('proxy')} / {j.get('hosting')}")


def whois_lookup():
    ui.banner_line("WHOIS")
    d = ui.ask("Dominio:")
    if not d:
        return
    ui.info("Consultando (IANA -> servidor autoritativo)...")
    print(B.GREY + net.whois_query(d)[:6000] + B.RESET)


def dns_records():
    ui.banner_line("Registros DNS  (resolver propio UDP)")
    d = ui.ask("Dominio:")
    if not d:
        return
    got = False
    for t in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        for r in net.dns_query(d, t):
            ui.item(r["type"], f"{r['value']}   (ttl {r['ttl']})")
            got = True
    if not got:
        ui.warn("Sin respuesta (UDP/53 bloqueado o dominio inexistente).")


def reverse_dns():
    ui.banner_line("Reverse DNS  (PTR)")
    ip = ui.ask("IP:")
    if not ip:
        return
    try:
        host, alias, _ = socket.gethostbyaddr(ip)
        ui.item("PTR", host)
        for a in alias:
            ui.item("alias", a)
    except Exception as e:
        ui.bad(f"Sin PTR: {e}")


def ssl_cert_info():
    ui.banner_line("Certificado SSL/TLS")
    host = ui.ask("Host (ej: github.com):")
    if not host:
        return
    port = 443
    if ":" in host:
        host, p = host.split(":", 1); port = int(p)

    ver = cipher = None
    try:                                    # 1) conexion sin verificar -> version+cipher
        ctx0 = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx0.wrap_socket(sock, server_hostname=host) as ss:
                ver, cipher = ss.version(), ss.cipher()
    except Exception as e:
        ui.bad(f"No conecta TLS: {e}"); return
    ui.item("TLS", f"{ver}  {cipher[0] if cipher else ''}")

    try:                                    # 2) conexion verificada -> detalles del cert
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        subj = dict(x[0] for x in cert.get("subject", []))
        iss = dict(x[0] for x in cert.get("issuer", []))
        ui.item("CN", subj.get("commonName"))
        ui.item("Emisor", iss.get("organizationName") or iss.get("commonName"))
        ui.item("Valido desde", cert.get("notBefore"))
        ui.item("Expira", cert.get("notAfter"))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        if sans:
            ui.item("SANs", ", ".join(sans[:15]) + (" ..." if len(sans) > 15 else ""))
    except ssl.SSLCertVerificationError as e:
        ui.warn(f"Cert presente pero no verificable (self-signed/expirado): {e}")
    except Exception as e:
        ui.warn(f"No se pudo parsear el cert: {e}")


def github_osint():
    ui.banner_line("GitHub OSINT")
    u = ui.ask("Usuario de GitHub:")
    if not u:
        return
    j, _err = net.http_json(f"https://api.github.com/users/{u}", timeout=10)
    if not j or "login" not in j:
        ui.bad("Usuario no encontrado o rate-limit de la API."); return
    ui.item("Login", j.get("login"))
    ui.item("Nombre", j.get("name"))
    ui.item("Bio", j.get("bio"))
    ui.item("Empresa", j.get("company"))
    ui.item("Ubicacion", j.get("location"))
    ui.item("Blog", j.get("blog"))
    ui.item("Twitter", j.get("twitter_username"))
    ui.item("Repos/Gists", f"{j.get('public_repos')} / {j.get('public_gists')}")
    ui.item("Seguidores", f"{j.get('followers')}  |  sigue a {j.get('following')}")
    ui.item("Creado", j.get("created_at"))
    ui.item("Perfil", j.get("html_url"))
    repos, _ = net.http_json(
        f"https://api.github.com/users/{u}/repos?per_page=100&sort=updated", timeout=10)
    if isinstance(repos, list) and repos:
        ui.info(f"Ultimos repos ({min(len(repos), 8)} de {len(repos)}):")
        langs = {}
        for r in repos[:8]:
            print(f"     {B.ORANGE}{r.get('name')}{B.RESET}  "
                  f"{B.GREY}\u2605{r.get('stargazers_count')} · {r.get('language') or '-'}{B.RESET}")
            if r.get("language"):
                langs[r["language"]] = langs.get(r["language"], 0) + 1
        if langs:
            top = sorted(langs.items(), key=lambda x: -x[1])
            ui.item("Lenguajes", ", ".join(f"{k}({v})" for k, v in top))


def wayback_urls():
    ui.banner_line("Wayback Machine  (archive.org)")
    d = ui.ask("Dominio (ej: example.com):")
    if not d:
        return
    url = (f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(d)}"
           f"/*&output=json&fl=original&collapse=urlkey&limit=80")
    j, err = net.http_json(url, timeout=18)
    if not isinstance(j, list) or len(j) < 2:
        ui.bad(f"Sin resultados en el archivo ({err})."); return
    urls = [row[0] for row in j[1:]]
    ui.good(f"{len(urls)} URLs archivadas (muestra):")
    for u in urls[:45]:
        print(f"     {B.GREY}{u}{B.RESET}")


def http_fingerprint():
    ui.banner_line("Fingerprint HTTP / Tecnologias")
    url = ui.ask("URL o host:")
    if not url:
        return
    code, hdrs, body, final = net.http_request(url, timeout=12)
    if code is None:
        ui.bad(f"No responde: {body.decode('utf-8', 'replace')[:80]}"); return
    ui.item("URL final", final)
    ui.item("Status", code)
    interesting = ("Server", "X-Powered-By", "Via", "X-AspNet-Version", "X-Generator",
                   "Content-Type", "X-Cache", "CF-RAY", "X-Served-By")
    lower = {k.lower(): v for k, v in hdrs.items()}
    for h in interesting:
        if h.lower() in lower:
            ui.item(h, lower[h.lower()][:110])
    txt = body.decode("utf-8", "replace")[:200000].lower()
    joined = txt + " " + " ".join(f"{k}:{v}" for k, v in hdrs.items()).lower()
    sigs = {
        "WordPress": ["wp-content", "wp-includes"], "Joomla": ["/media/jui/", "joomla"],
        "Drupal": ["sites/default/files", "drupal"],
        "React": ["data-reactroot", "__react"], "Vue.js": ["__vue__", "vue.js"],
        "Angular": ["ng-version", "ng-app"], "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap.min", "bootstrap.css"], "Cloudflare": ["cf-ray", "cloudflare"],
        "Nginx": ["nginx"], "Apache": ["apache"], "PHP": ["phpsessid", "x-powered-by:php"],
        "Laravel": ["laravel_session", "xsrf-token"], "Next.js": ["/_next/", "__next"],
        "WooCommerce": ["woocommerce"], "Shopify": ["cdn.shopify"], "Wix": ["static.wixstatic"],
    }
    tech = sorted({name for name, keys in sigs.items() if any(k in joined for k in keys)})
    ui.item("Detectado", ", ".join(tech) or "nada evidente")
    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.S)
    if m:
        ui.item("Title", m.group(1).strip()[:100])


# codigos de pais mas comunes (metadata offline; no exhaustivo)
CC = {
    "1": "USA/Canada", "7": "Rusia/Kazajistan", "20": "Egipto", "27": "Sudafrica",
    "30": "Grecia", "31": "Paises Bajos", "32": "Belgica", "33": "Francia", "34": "Espana",
    "351": "Portugal", "352": "Luxemburgo", "353": "Irlanda", "354": "Islandia",
    "355": "Albania", "356": "Malta", "357": "Chipre", "358": "Finlandia", "359": "Bulgaria",
    "36": "Hungria", "39": "Italia", "40": "Rumania", "41": "Suiza", "43": "Austria",
    "44": "Reino Unido", "45": "Dinamarca", "46": "Suecia", "47": "Noruega", "48": "Polonia",
    "49": "Alemania", "51": "Peru", "52": "Mexico", "53": "Cuba", "54": "Argentina",
    "55": "Brasil", "56": "Chile", "57": "Colombia", "58": "Venezuela", "60": "Malasia",
    "61": "Australia", "62": "Indonesia", "63": "Filipinas", "64": "Nueva Zelanda",
    "65": "Singapur", "66": "Tailandia", "81": "Japon", "82": "Corea del Sur", "84": "Vietnam",
    "86": "China", "90": "Turquia", "91": "India", "92": "Pakistan", "93": "Afganistan",
    "212": "Marruecos", "213": "Argelia", "216": "Tunez", "234": "Nigeria", "254": "Kenia",
    "351": "Portugal", "505": "Nicaragua", "506": "Costa Rica", "507": "Panama",
    "591": "Bolivia", "593": "Ecuador", "595": "Paraguay", "598": "Uruguay",
    "880": "Bangladesh", "886": "Taiwan", "966": "Arabia Saudi", "971": "EAU",
    "972": "Israel", "977": "Nepal", "98": "Iran",
}


def phone_info():
    ui.banner_line("Phone Info  (offline, E.164)")
    raw = ui.ask("Numero con prefijo (ej +34600...):")
    if not raw:
        return
    num = re.sub(r"[^\d+]", "", raw)
    if not num.startswith("+"):
        ui.warn("Sin '+'; asumiendo que ya incluye el codigo de pais.")
    digits = num.lstrip("+")
    cc = country = None
    for length in (3, 2, 1):
        if digits[:length] in CC:
            cc, country = digits[:length], CC[digits[:length]]; break
    ui.item("Entrada", raw)
    ui.item("Normalizado", ("+" + digits))
    ui.item("Codigo pais", f"+{cc} -> {country}" if cc else "desconocido")
    nat = digits[len(cc):] if cc else digits
    ui.item("Numero nacional", nat)
    ui.item("Longitud total", f"{len(digits)} digitos")
    if cc == "34" and nat:
        tipo = {"6": "Movil", "7": "Movil", "9": "Fijo/Geografico",
                "8": "Fijo/Servicios"}.get(nat[0], "?")
        ui.item("Tipo (ES)", tipo)
    ui.info("Metadatos offline. Para portabilidad/operador real hace falta HLR lookup (API).")


SITES = {
    "GitHub": "https://github.com/{}", "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}", "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}", "Twitch": "https://www.twitch.tv/{}",
    "Pinterest": "https://www.pinterest.com/{}/", "Telegram": "https://t.me/{}",
    "Steam": "https://steamcommunity.com/id/{}", "Medium": "https://medium.com/@{}",
    "Dev.to": "https://dev.to/{}", "Keybase": "https://keybase.io/{}",
    "HackerOne": "https://hackerone.com/{}", "Replit": "https://replit.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}", "Patreon": "https://www.patreon.com/{}",
    "About.me": "https://about.me/{}", "Gravatar": "https://gravatar.com/{}",
}


def username_search():
    ui.banner_line("Username OSINT  (presencia en redes)")
    u = ui.ask("Username:")
    if not u:
        return
    ui.info(f"Comprobando {len(SITES)} sitios...")

    def check(item):
        name, tmpl = item
        url = tmpl.format(u)
        code, _h, _b, final = net.http_request(url, timeout=8)
        if code is None:
            return (name, url, "err")
        if code == 200:
            return (name, url, "HIT")
        if code in (301, 302):
            return (name, final, "redir")
        if code == 404:
            return (name, url, "no")
        return (name, url, str(code))

    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for name, url, status in ex.map(check, SITES.items()):
            if status == "HIT":
                ui.good(f"{name:<12} {url}")
            elif status != "no":
                ui.warn(f"{name:<12} [{status}] {url}")
    ui.info("Nota: sitios anti-bot pueden devolver 200/403 sin fiabilidad. Verifica manual.")


TOOLS = [
    ("1", "IP / Host Info", ip_info),
    ("2", "WHOIS", whois_lookup),
    ("3", "Registros DNS", dns_records),
    ("4", "Reverse DNS (PTR)", reverse_dns),
    ("5", "Certificado SSL/TLS", ssl_cert_info),
    ("6", "GitHub OSINT", github_osint),
    ("7", "Wayback Machine", wayback_urls),
    ("8", "Fingerprint HTTP / Tech", http_fingerprint),
    ("9", "Phone Info (offline)", phone_info),
    ("10", "Username OSINT", username_search),
]


def menu():
    while True:
        ui.clear()
        ui.menu("OSINT & RECONOCIMIENTO", [(k, l) for k, l, _ in TOOLS])
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
