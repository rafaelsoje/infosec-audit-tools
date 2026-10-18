#!/usr/bin/env python3
"""
Passive SSL/TLS & Certificate Security Auditor
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Auditor passivo de infraestrutura criptográfica SSL/TLS:
- Inspeciona versão do protocolo negociado (TLS 1.2, TLS 1.3)
- Alerta sobre protocolos legados/inseguros (SSLv3, TLS 1.0, TLS 1.1)
- Analisa certificado X.509: Emissor (CA), dias até expiração e SANs
- Descobre subdomínios e domínios correlacionados via Subject Alternative Names (SANs)
"""

import argparse
from datetime import datetime, timezone
import socket
import ssl
import sys
from urllib.parse import urlparse


def parse_target(target: str):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    port = parsed.port or 443
    return hostname, port


def audit_ssl_tls(hostname: str, port: int = 443):
    print("=" * 70)
    print(f" Auditoria de Segurança SSL/TLS: {hostname}:{port}")
    print("=" * 70)

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                protocol_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

        print("\n[+] Protocolo Criptográfico & Ciphers:")
        print(f"  • Versão Negociada: {protocol_version}")
        if protocol_version in ("TLSv1.3", "TLSv1.2"):
            print("  [✔] Protocolo seguro e moderno em conformidade.")
        else:
            print(f"  [🚨 ALERTA] Protocolo obsoleto/inseguro detectado: {protocol_version}!")

        if cipher:
            cipher_name, ssl_ver, secret_bits = cipher
            print(f"  • Cipher Suite:     {cipher_name} ({secret_bits} bits)")

        # ----------------------------------------------------------------------
        # Análise do Certificado X.509
        # ----------------------------------------------------------------------
        print("\n[+] Certificado Digital X.509:")
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        print(f"  • Common Name (CN): {subject.get('commonName', 'N/A')}")
        print(f"  • Autoridade (CA):  {issuer.get('organizationName', issuer.get('commonName', 'N/A'))}")

        # Validade temporal
        not_after_str = cert.get("notAfter")
        if not_after_str:
            # Formato padrão SSL: 'Mar  8 12:00:00 2026 GMT'
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days

            print(f"  • Expira em:        {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} ({days_left} dias restantes)")
            if days_left < 0:
                print("  [🚨 ALERTA] O certificado está EXPIRADO!")
            elif days_left < 15:
                print("  [⚠️ AVISO] Certificado próximo da expiração (< 15 dias)!")
            else:
                print("  [✔] Validade em conformidade.")

        # ----------------------------------------------------------------------
        # Descoberta de Superfície via SANs (Subject Alternative Names)
        # ----------------------------------------------------------------------
        sans = cert.get("subjectAltName", [])
        dns_sans = [val for typ, val in sans if typ == "DNS"]

        print(f"\n[+] Domínios Alternativos Mapeados (SANs: {len(dns_sans)}):")
        for domain in sorted(set(dns_sans)):
            print(f"  • {domain}")

        print("\n" + "=" * 70)
        print(" Diagnóstico Final: Auditoria concluída com sucesso.")
        print("=" * 70)

    except socket.gaierror:
        print(f"[ERRO] Falha ao resolver endereço DNS para: {hostname}", file=sys.stderr)
    except socket.timeout:
        print(f"[ERRO] Conexão expirou (timeout) ao conectar a: {hostname}:{port}", file=sys.stderr)
    except ssl.SSLCertVerificationError as e:
        print(f"[🚨 FALHA DE CERTIFICADO] Erro de validação SSL: {e}", file=sys.stderr)
    except ssl.SSLError as e:
        print(f"[ERRO] Erro de handshake SSL/TLS: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERRO] Erro inesperado: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditor passivo de certificados e protocolos SSL/TLS.")
    parser.add_argument("host", help="Hostname ou URL do servidor a ser auditado (ex: exemplo.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Porta SSL/TLS (padrão: 443)")
    args = parser.parse_args()

    target_host, target_port = parse_target(args.host)
    if args.port != 443:
        target_port = args.port

    audit_ssl_tls(target_host, target_port)
