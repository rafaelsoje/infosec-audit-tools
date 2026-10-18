#!/usr/bin/env python3
"""
Passive Subdomain Reconnaissance via Certificate Transparency (crt.sh)
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Mapeamento passivo de subdomínios e ativos de rede corporativos
através de registros públicos de Certificate Transparency (CT Logs).
100% passivo: nenhum pacote direto é enviado ao host alvo durante a busca.
"""

import argparse
import csv
import json
from pathlib import Path
import socket
import sys
import urllib.error
import urllib.request


def resolve_subdomain(domain: str) -> bool:
    """Verifica se o subdomínio possui resolução DNS ativa (A/AAAA)."""
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


def fetch_subdomains(target_domain: str) -> set:
    target_domain = target_domain.lower().strip()
    if target_domain.startswith("http://") or target_domain.startswith("https://"):
        target_domain = target_domain.split("://")[1].split("/")[0]

    url = f"https://crt.sh/?q=%.{target_domain}&output=json"
    print(f"[+] Consultando Certificate Transparency Logs para: '*.{target_domain}'...")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SecRecon-CTLogs/1.0 (Authorized Security Audit)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[ERRO] Falha na consulta HTTP ({e.code}): {e.reason}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"[ERRO] Falha ao conectar ao serviço crt.sh: {e}", file=sys.stderr)
        return set()

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        # crt.sh pode retornar múltiplos nomes separados por quebra de linha
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name and (name == target_domain or name.endswith("." + target_domain)):
                subdomains.add(name)

    return subdomains


def main():
    parser = argparse.ArgumentParser(
        description="Mapeador passivo de subdomínios via Certificate Transparency (crt.sh)."
    )
    parser.add_argument("domain", help="Domínio raiz alvo (ex: empresa.com.br)")
    parser.add_argument("--resolve", action="store_true", help="Testar resolução DNS ativa de cada subdomínio")
    parser.add_argument("-o", "--output", help="Arquivo CSV para exportação dos resultados")
    args = parser.parse_args()

    found_domains = fetch_subdomains(args.domain)

    if not found_domains:
        print("[i] Nenhum subdomínio encontrado nos logs de transparência.")
        sys.exit(0)

    print(f"\n[✔] {len(found_domains)} subdomínios únicos identificados nos registros CT:\n")

    results = []
    for sub in sorted(found_domains):
        if args.resolve:
            is_active = resolve_subdomain(sub)
            status_str = "[ONLINE]" if is_active else "[INATIVO]"
            print(f"  {status_str:9} {sub}")
            results.append({"subdomain": sub, "resolves": is_active})
        else:
            print(f"  • {sub}")
            results.append({"subdomain": sub})

    if args.output:
        out_path = Path(args.output)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            fieldnames = ["subdomain"]
            if args.resolve:
                fieldnames.append("resolves")
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"\n[+] Relatório exportado com sucesso para: {out_path.resolve()}")


if __name__ == "__main__":
    main()
