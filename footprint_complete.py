#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
footprint_complete.py
Versión con controles de autorización para condicionar acciones (TLS, HTTP, Shodan).
Uso:
  pip install dnspython requests cryptography python-whois beautifulsoup4
  python3 footprint_complete.py --target testphp.vulnweb.com [--authorize] [--auth-token <token>]
Opcional:
  --shodan-key <key>
También puedes exportar:
  export FOOTPRINT_AUTHORIZED=1
  export FOOTPRINT_AUTH_TOKEN="mi_token"
"""
from __future__ import annotations
import argparse
import csv
import datetime
import json
import os
import socket
import ssl
import sys
import time
from typing import Any, Dict, List, Optional

import dns.resolver
import requests
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup

# Controles
AUTHORIZED = False  # valor por defecto; puede habilitarse vía CLI o variables de entorno
DEFAULT_TARGET = "testphp.vulnweb.com"

# Config
HTTP_HEADERS = {"User-Agent": "FootprintScript/1.0 (+https://example.local)"}
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 10
TLS_TIMEOUT = 8
RETRIES = 3
RETRY_DELAY = 1.5

def ts() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"

def save_json(obj: Dict[str, Any], fname: str = "output_passive.json") -> None:
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def save_subdomains_csv(subs: List[str], fname: str = "subdomains.csv") -> None:
    with open(fname, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subdomain","found_at"])
        for s in subs:
            w.writerow([s, ts()])

def retry_request(url: str, **kwargs) -> Optional[requests.Response]:
    for i in range(RETRIES):
        try:
            return requests.get(url, timeout=kwargs.get("timeout", HTTP_TIMEOUT), headers=HTTP_HEADERS, allow_redirects=True)
        except Exception as e:
            last = e
            time.sleep(RETRY_DELAY)
    # si falla
    raise last

def dns_queries(domain: str) -> Dict[str, List[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    types = ["A","AAAA","MX","NS","TXT","CNAME"]
    out: Dict[str, List[str]] = {}
    for t in types:
        try:
            answers = resolver.resolve(domain, t, lifetime=DNS_TIMEOUT)
            out[t] = [str(r).strip() for r in answers]
        except Exception as e:
            out[t] = []
    return out

def whois_with_fallback(domain: str) -> Dict[str, Any]:
    # Intento 1: python-whois
    try:
        w = whois.whois(domain)
        try:
            d = dict(w)
        except Exception:
            d = {k: v for k, v in w.items()}
        # serializa datetimes y sets
        for k, v in list(d.items()):
            if isinstance(v, set):
                d[k] = list(v)
            if hasattr(v, "isoformat"):
                try:
                    d[k] = v.isoformat()
                except Exception:
                    pass
        return {"source": "python-whois", "data": d}
    except Exception as e:
        err1 = str(e)

    # Intento 2: RDAP público (fallback)
    rdap_url = f"https://rdap.org/domain/{domain}"
    try:
        for _ in range(RETRIES):
            r = requests.get(rdap_url, timeout=HTTP_TIMEOUT, headers=HTTP_HEADERS)
            if r.status_code == 200:
                try:
                    j = r.json()
                    return {"source": "rdap.org", "data": j}
                except Exception as e:
                    return {"source": "rdap.org", "error": f"json_error:{e}", "status": r.status_code}
            else:
                time.sleep(RETRY_DELAY)
        return {"error": f"rdap_status_{r.status_code}", "rdap_url": rdap_url, "python_whois_error": err1}
    except Exception as e:
        return {"error": f"rdap_exception:{e}", "python_whois_error": err1}

def query_crtsh(domain: str) -> Dict[str, Any]:
    """
    intenta crt.sh con reintentos; devuelve dict con "subs" (lista) o error
    """
    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json"
    ]
    last_err = None
    for url in urls:
        for i in range(RETRIES):
            try:
                r = requests.get(url, timeout=HTTP_TIMEOUT, headers=HTTP_HEADERS)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        subs = set()
                        for entry in data:
                            nv = entry.get("name_value")
                            if nv:
                                for line in nv.splitlines():
                                    n = line.strip().lstrip("*.").rstrip(".").lower()
                                    if n:
                                        subs.add(n)
                        return {"subs": sorted(subs)}
                    except Exception as e:
                        return {"error": f"crt_json_error:{e}", "status": r.status_code}
                else:
                    last_err = f"status_{r.status_code}"
            except Exception as e:
                last_err = str(e)
            time.sleep(RETRY_DELAY)
    return {"error": f"crt_failed:{last_err}"}

def tls_info(domain: str, port: int = 443) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                subj = {}
                for rdn in cert.subject.rdns:
                    for attr in rdn:
                        subj[attr.oid._name] = attr.value
                iss = {}
                for rdn in cert.issuer.rdns:
                    for attr in rdn:
                        iss[attr.oid._name] = attr.value
                info = {
                    "subject": subj,
                    "issuer": iss,
                    "not_before": cert.not_valid_before.isoformat(),
                    "not_after": cert.not_valid_after.isoformat(),
                    "serial_number": str(cert.serial_number)
                }
                try:
                    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    info["alt_names"] = san.value.get_values_for_type(x509.DNSName)
                except Exception:
                    info["alt_names"] = []
        return info
    except Exception as e:
        return {"error": f"tls_error:{e}"}

def fetch_http_info(target: str) -> Dict[str, Any]:
    """
    Intentará HTTP y HTTPS, obtiene headers, robots, sitemap y extrae links (passivo).
    """
    out: Dict[str, Any] = {}
    candidates = [f"https://{target}", f"http://{target}"]
    for url in candidates:
        try:
            r = retry_request(url, timeout=HTTP_TIMEOUT)
            out["url"] = url
            out["timestamp"] = ts()
            out["status_code"] = r.status_code
            out["headers"] = dict(r.headers)
            out["final_url"] = r.url
            # robots
            try:
                base = r.url.split("/",3)[:3]
                base = base[0] + "//" + base[2] if len(base)>=3 else r.url
            except Exception:
                base = f"https://{target}"
            try:
                robots = requests.get(base + "/robots.txt", timeout=5, headers=HTTP_HEADERS)
                out["robots_txt"] = {"status": robots.status_code, "body": robots.text}
            except Exception as e:
                out["robots_txt"] = {"error": str(e)}
            # sitemaps comunes
            sitemaps = {}
            for p in ["/sitemap.xml", "/sitemap_index.xml"]:
                try:
                    r2 = requests.get(base + p, timeout=5, headers=HTTP_HEADERS)
                    sitemaps[p] = {"status": r2.status_code, "body_sample": r2.text[:300]}
                except Exception as e:
                    sitemaps[p] = {"error": str(e)}
            out["sitemaps"] = sitemaps
            # parse links
            try:
                soup = BeautifulSoup(r.text or "", "html.parser")
                links = [a.get("href") for a in soup.find_all("a", href=True)]
                out["links_found"] = links
            except Exception as e:
                out["links_found_error"] = str(e)
            return out
        except Exception as e:
            # intentar siguiente (https->http)
            last_err = str(e)
            continue
    return {"error": f"http_attempts_failed:{last_err}"}

def shodan_lookup(target: str, key: Optional[str]) -> Dict[str, Any]:
    if not key:
        return {"note": "no shodan key provided"}
    try:
        import shodan
        api = shodan.Shodan(key)
        # intenta resolver a IPs
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=DNS_TIMEOUT)
            ips = [str(x) for x in answers]
        except Exception:
            ips = [target]
        out = {}
        for ip in ips:
            try:
                out[ip] = api.host(ip)
            except Exception as e:
                out[ip] = {"error": str(e)}
        return out
    except Exception as e:
        return {"error": f"shodan_lib_issue:{e}"}

def parse_authorization(args: argparse.Namespace) -> bool:
    """
    Determina si la ejecución está 'autorizada' (por variable global, flag, o token en entorno).
    """
    # 1) variable global en el código (puede modificarse antes de ejecutar)
    if AUTHORIZED:
        return True
    # 2) flag CLI --authorize
    if getattr(args, "authorize", False):
        return True
    # 3) variable de entorno corta
    env_flag = os.environ.get("FOOTPRINT_AUTHORIZED")
    if env_flag and env_flag.strip() in ("1", "true", "True", "yes", "y"):
        return True
    # 4) token match: --auth-token debe coincidir con FOOTPRINT_AUTH_TOKEN
    provided = getattr(args, "auth_token", None)
    if provided:
        expected = os.environ.get("FOOTPRINT_AUTH_TOKEN")
        if expected and provided == expected:
            return True
    return False

def build_report(target: str, shodan_key: Optional[str] = None, authorized: bool = False) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "metadata": {"target": target, "collected_at": ts(), "tool": "footprint_complete.py", "authorized": authorized},
        "dns": {}, "whois": {}, "shodan": {}, "subdominios": [], "tls": {}, "http": {}
    }

    # DNS (siempre)
    try:
        report["dns"] = dns_queries(target)
    except Exception as e:
        report["dns"] = {"error": str(e)}

    # WHOIS / RDAP (siempre - lectura pública)
    report["whois"] = whois_with_fallback(target)

    # crt.sh (siempre)
    report_crt = query_crtsh(target)
    if "subs" in report_crt:
        subs = set(report_crt["subs"])
    else:
        subs = set()
    report["crtsh"] = report_crt

    # guesses via DNS common subs
    commons = ["www","api","admin","test","dev","mail","ftp","portal","staging","beta"]
    for c in commons:
        fq = f"{c}.{target}"
        try:
            answers = dns.resolver.resolve(fq, "A", lifetime=DNS_TIMEOUT)
            if answers:
                subs.add(fq)
        except Exception:
            pass
    # ensure root
    subs.add(target)
    report["subdominios"] = sorted(subs)

    # TLS: solo si autorizado
    if authorized:
        report["tls"] = tls_info(target, port=443)
    else:
        report["tls"] = {"skipped": "not_authorized", "note": "TLS handshake/info requires --authorize or env FOOTPRINT_AUTHORIZED"}

    # HTTP/HTTPS headers & links: solo si autorizado
    if authorized:
        report["http"] = fetch_http_info(target)
    else:
        report["http"] = {"skipped": "not_authorized", "note": "HTTP fetch requires --authorize or env FOOTPRINT_AUTHORIZED"}

    # Shodan (opcional) — además requiere autorización explícita
    if authorized:
        report["shodan"] = shodan_lookup(target, shodan_key)
    else:
        report["shodan"] = {"skipped": "not_authorized", "note": "Shodan lookup requires authorization (and --shodan-key)"}

    return report

def main():
    p = argparse.ArgumentParser(description="Footprint completo (pasivo) con reintentos y fallback. Algunas acciones requieren autorización.")
    p.add_argument("--target", default=DEFAULT_TARGET)
    p.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"))
    p.add_argument("--authorize", action="store_true", help="Habilita acciones que requieren autorización (TLS, HTTP, Shodan).")
    p.add_argument("--auth-token", default=None, help="Token para autorizar (compara con FOOTPRINT_AUTH_TOKEN en entorno).")
    args = p.parse_args()

    target = args.target.strip()
    authorized = parse_authorization(args)

    print(f"[{ts()}] iniciando recoleccion para: {target}")
    if authorized:
        print(f"[{ts()}] modo AUTORIZADO: TLS, HTTP y Shodan están habilitados.")
    else:
        print(f"[{ts()}] modo NO autorizado: TLS/HTTP/Shodan serán saltados. Ejecuta con --authorize o export FOOTPRINT_AUTHORIZED=1 para habilitarlos.")

    report = build_report(target, args.shodan_key, authorized=authorized)

    save_json(report, "output_passive.json")
    print(f"[{ts()}] guardado output_passive.json")

    save_subdomains_csv(report.get("subdominios", []), "subdomains.csv")
    print(f"[{ts()}] guardado subdomains.csv (entradas: {len(report.get('subdominios', []))})")

    print(f"[{ts()}] FIN")

if __name__ == "__main__":
	main()

