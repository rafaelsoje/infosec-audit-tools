#!/usr/bin/env python3
"""
Domain Availability & Reconnaissance Checker
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Verificador assíncrono de disponibilidade e inteligência de domínios via DNS (A/AAAA)
e consultas oficiais aos servidores RDAP (Verisign, Registro.br, rdap.org).
"""

import argparse
import asyncio
import csv
from pathlib import Path
import re
import socket
import sys

try:
    import aiohttp
except ImportError:
    print("[ERRO] Biblioteca 'aiohttp' não instalada. Instale com: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

# Configurações padrão
CONCURRENCY = 20
TIMEOUT_SECONDS = 8


def slugify(name: str) -> str:
    """Normaliza o nome para virar label de domínio compatível (a-z0-9 e hífen)."""
    name = name.strip().lower()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^a-z0-9-]", "", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name


def dns_resolve(domain: str) -> bool:
    """Retorna True se o domínio resolver via DNS oficial (registros A ou AAAA)."""
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


async def rdap_check(session: aiohttp.ClientSession, domain: str) -> str:
    """
    Consulta serviços RDAP autoritativos.
    Retorna:
      - 'registered': se RDAP confirmar registro ativo (HTTP 200)
      - 'available': se RDAP confirmar inexistência (HTTP 404/410)
      - 'unknown': em caso de timeout, rate limit ou indisponibilidade
    """
    if domain.endswith(".com"):
        urls = [
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
            f"https://rdap.org/domain/{domain}",
        ]
    elif domain.endswith(".com.br"):
        urls = [
            f"https://rdap.registro.br/domain/{domain}",
            f"https://rdap.org/domain/{domain}",
        ]
    else:
        urls = [f"https://rdap.org/domain/{domain}"]

    for url in urls:
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return "registered"
                if resp.status in (404, 410):
                    return "available"
        except Exception:
            pass

    return "unknown"


async def check_domain(sem: asyncio.Semaphore, session: aiohttp.ClientSession, domain: str) -> dict:
    async with sem:
        resolves = dns_resolve(domain)
        rdap = await rdap_check(session, domain)

        if rdap == "registered":
            status = "registered"
            confidence = "high"
        elif rdap == "available":
            status = "available"
            confidence = "high"
        else:
            status = "registered?" if resolves else "available?"
            confidence = "low"

        return {
            "domain": domain,
            "dns_resolves": str(resolves).lower(),
            "rdap": rdap,
            "status": status,
            "confidence": confidence,
        }


async def main():
    parser = argparse.ArgumentParser(
        description="Verificador assíncrono de disponibilidade e inteligência de domínios via RDAP e DNS."
    )
    parser.add_argument("input_file", help="Arquivo .txt contendo termos/nomes (um por linha)")
    parser.add_argument(
        "-o", "--output",
        default="disponiveis.csv",
        help="Arquivo de saída (CSV) para gravação dos domínios disponíveis (padrão: disponiveis.csv)"
    )
    parser.add_argument(
        "--tlds",
        default="com,com.br",
        help="Lista de TLDs separados por vírgula (ex: com,com.br,net,org)"
    )
    parser.add_argument(
        "--only-print",
        action="store_true",
        help="Apenas exibe os resultados no terminal sem gravar arquivo"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=CONCURRENCY,
        help="Número de requisições simultâneas em paralelo (padrão: 20)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT_SECONDS,
        help="Timeout por requisição HTTP em segundos (padrão: 8)"
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.exists():
        sys.exit(f"[ERRO] Arquivo de entrada não encontrado: {input_path}")

    tlds = [t.strip() for t in args.tlds.split(",") if t.strip()]
    if not tlds:
        sys.exit("[ERRO] Informe ao menos um TLD em --tlds")

    raw_lines = input_path.read_text(encoding="utf-8", errors="replace").splitlines()
    names = [slugify(line) for line in raw_lines if slugify(line)]

    if not names:
        sys.exit("[ERRO] Nenhum nome válido encontrado no arquivo fornecido.")

    domains = [f"{name}.{tld}" for name in names for tld in tlds]
    print(f"[+] Total de combinações a verificar: {len(domains)} domínios...")

    sem = asyncio.Semaphore(args.concurrency)
    timeout = aiohttp.ClientTimeout(total=args.timeout)

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": "SecRecon-DomainCheck/1.0"}
    ) as session:
        results = await asyncio.gather(*(check_domain(sem, session, d) for d in domains))

    available = [r for r in results if r["status"] == "available" and r["confidence"] == "high"]

    print("\n" + "=" * 50)
    print(" DOMÍNIOS DISPONÍVEIS CONFIRMADOS (RDAP):")
    print("=" * 50)
    for r in available:
        print(f" [✔] {r['domain']}")

    print(f"\nResumo: {len(available)} disponíveis de {len(results)} verificados.")

    if not args.only_print and available:
        out_path = Path(args.output)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["domain"])
            writer.writeheader()
            for r in available:
                writer.writerow({"domain": r["domain"]})
        print(f"[+] Resultados exportados para: {out_path.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())

