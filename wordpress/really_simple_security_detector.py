#!/usr/bin/env python3
"""
Really Simple Security / Really Simple SSL Plugin & Header Detector
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Auditor passivo para identificação do plugin Really Simple Security (WordPress),
leitura remota de versão do changelog e auditoria de cabeçalhos HTTP de segurança.
"""

import argparse
import re
import sys
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("[ERRO] Biblioteca 'requests' não instalada. Instale com: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Permissions-Policy",
    "Referrer-Policy"
]


def audit_wordpress_security(target_url: str):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    print("=" * 60)
    print(f" Auditoria Passiva: {target_url}")
    print("=" * 60)

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecAudit/1.0"})

        # 1. Auditoria de Cabeçalhos HTTP
        head_resp = session.head(target_url, allow_redirects=True, timeout=10)
        headers = head_resp.headers

        print("\n[+] Análise de Cabeçalhos de Segurança HTTP:")
        present_headers = [h for h in SECURITY_HEADERS if h in headers]
        missing_headers = [h for h in SECURITY_HEADERS if h not in headers]

        for h in present_headers:
            print(f"  [✔] {h}: {headers[h]}")

        for h in missing_headers:
            print(f"  [✘] {h}: Ausente")

        # 2. Varredura do HTML da Home
        get_resp = session.get(target_url, timeout=10)
        html = get_resp.text.lower()

        signatures = [
            "really-simple-ssl",
            "really-simple-security",
            "wp-content/plugins/really-simple-ssl",
            "wp-content/plugins/really-simple-security"
        ]
        found_signatures = [s for s in signatures if s in html]

        print("\n[+] Análise de Assinaturas no Código-Fonte HTML:")
        if found_signatures:
            for s in found_signatures:
                print(f"  [✔] Assinatura detectada: {s}")
        else:
            print("  [i] Nenhuma menção explícita encontrada no HTML da página inicial.")

        # 3. Tentar extração da versão via readme.txt público
        readme_url = urljoin(target_url, "/wp-content/plugins/really-simple-ssl/readme.txt")
        readme_resp = session.get(readme_url, timeout=10)

        version_detected = None
        if readme_resp.status_code == 200:
            match = re.search(r'==\s*Changelog\s*==.*?\n\s*(\d+\.\d+\.\d+)', readme_resp.text, re.DOTALL)
            if match:
                version_detected = match.group(1)

        print("\n[+] Auditoria de Arquivo de Metadados (readme.txt):")
        if readme_resp.status_code == 200:
            print(f"  [!] Arquivo acessível publicamente: {readme_url}")
            if version_detected:
                print(f"  [!] Versão detectada: {version_detected}")
                # Verificação de vulnerabilidade conhecida para CVE-2024-10924 (versões < 9.1.2)
                major_minor_patch = [int(p) for p in version_detected.split(".") if p.isdigit()]
                if len(major_minor_patch) >= 2 and major_minor_patch < [9, 1, 2]:
                    print("  [🚨 ALERTA CRÍTICO] Versão potencialmente vulnerável ao CVE-2024-10924 (< 9.1.2)!")
                else:
                    print("  [✔] Versão atualizada contra CVE-2024-10924 (>= 9.1.2).")
        else:
            print("  [✔] Arquivo readme.txt protegido ou inexistente (HTTP != 200).")

        print("\n" + "=" * 60)
        print(" Diagnóstico Final:")
        if present_headers or found_signatures or (readme_resp.status_code == 200):
            print(" [✔] O alvo apresenta fortes indícios do uso de Really Simple Security.")
        else:
            print(" [i] Nenhuma evidência do plugin Really Simple Security foi identificada.")
        print("=" * 60)

    except requests.RequestException as e:
        print(f"[ERRO] Falha de comunicação com o host: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditor de segurança e detector de Really Simple Security.")
    parser.add_argument("url", help="URL do site WordPress (ex: https://exemplo.com)")
    args = parser.parse_args()

    audit_wordpress_security(args.url)
