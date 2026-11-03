#!/usr/bin/env python3
"""
HTTP Defensive Security Headers Auditor
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Auditor de cabeçalhos HTTP defensivos baseado no OWASP Secure Headers Project:
- Analisa cabeçalhos essenciais: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.
- Detecta vazamento de informações e versões em cabeçalhos (Server, X-Powered-By, etc.)
- Calcula pontuação técnica e nota de conformidade de A+ a F
- Emite recomendações de remediação e suporta exportação em JSON
"""

import argparse
from datetime import datetime, timezone
import json
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[ERRO] Biblioteca 'requests' não encontrada. Instale via: pip install requests", file=sys.stderr)
    sys.exit(1)


# Definição dos cabeçalhos de segurança avaliados
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "required": True,
        "description": "Força conexões HTTPS e mitiga ataques de SSL Stripping / downgrade.",
        "validate": lambda val: validate_hsts(val),
    },
    "Content-Security-Policy": {
        "weight": 25,
        "required": True,
        "description": "Restringe fontes de execução de scripts e mitiga Cross-Site Scripting (XSS) e Data Injection.",
        "validate": lambda val: validate_csp(val),
    },
    "X-Frame-Options": {
        "weight": 15,
        "required": True,
        "description": "Protege contra ataques de Clickjacking ao impedir renderização em iframes não autorizados.",
        "validate": lambda val: validate_xfo(val),
    },
    "X-Content-Type-Options": {
        "weight": 10,
        "required": True,
        "description": "Impede que navegadores executem MIME-sniffing em respostas recebidas.",
        "validate": lambda val: (val.strip().lower() == "nosniff", "Configurado corretamente com 'nosniff'" if val.strip().lower() == "nosniff" else "Valor recomendado: 'nosniff'"),
    },
    "Referrer-Policy": {
        "weight": 10,
        "required": True,
        "description": "Controla a quantidade de informações de referência (Referer) enviadas em requisições externas.",
        "validate": lambda val: validate_referrer_policy(val),
    },
    "Permissions-Policy": {
        "weight": 10,
        "required": False,
        "description": "Controla o acesso a recursos do navegador e hardware (câmera, microfone, geolocalização).",
        "validate": lambda val: (len(val.strip()) > 0, "Permissions-Policy definida"),
    },
    "Cross-Origin-Opener-Policy": {
        "weight": 5,
        "required": False,
        "description": "Garante isolamento do contexto de navegação contra ataques de vazamento entre origens.",
        "validate": lambda val: (val.strip().lower() in ("same-origin", "same-origin-allow-popups"), "COOP configurado com política de isolamento"),
    },
    "Cross-Origin-Resource-Policy": {
        "weight": 5,
        "required": False,
        "description": "Bloqueia carregamento de recursos do site por terceiros não autorizados.",
        "validate": lambda val: (val.strip().lower() in ("same-origin", "same-site"), "CORP configurado com restrição de origem"),
    },
}

# Cabeçalhos indicativos de vazamento de informações (Information Disclosure)
INFORMATION_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",
    "X-Version",
    "X-Generator",
]


def validate_hsts(value: str):
    val_lower = value.lower()
    if "max-age=" not in val_lower:
        return False, "Diretiva 'max-age' não encontrada no HSTS"
    
    # Extrair valor de max-age
    max_age_part = [p for p in val_lower.split(";") if "max-age=" in p]
    try:
        max_age = int(max_age_part[0].split("=")[1].strip())
        if max_age < 15552000:
            return False, f"max-age ({max_age}s) é menor que 180 dias. Recomendado: >= 31536000 (1 ano)"
    except (ValueError, IndexError):
        return False, "Valor de max-age inválido"
    
    details = []
    if "includesubdomains" in val_lower:
        details.append("includeSubDomains ativo")
    if "preload" in val_lower:
        details.append("preload ativo")
    
    detail_str = f"max-age={max_age}s" + (f" ({', '.join(details)})" if details else "")
    return True, detail_str


def validate_csp(value: str):
    issues = []
    val_lower = value.lower()
    
    if "'unsafe-inline'" in val_lower:
        issues.append("permite 'unsafe-inline' (risco de XSS)")
    if "'unsafe-eval'" in val_lower:
        issues.append("permite 'unsafe-eval' (execução de strings)")
    
    if issues:
        return False, f"CSP presente com advertências: {'; '.join(issues)}"
    return True, "Diretivas CSP robustas definidas sem unsafe-inline ou unsafe-eval"


def validate_xfo(value: str):
    val = value.strip().upper()
    if val in ("DENY", "SAMEORIGIN"):
        return True, f"Proteção ativa com '{val}'"
    return False, f"Valor '{val}' inseguro ou obsoleto. Use 'DENY' ou 'SAMEORIGIN'"


def validate_referrer_policy(value: str):
    secure_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
    }
    val = value.strip().lower()
    if any(p in val for p in secure_policies):
        return True, f"Política segura: '{value.strip()}'"
    return False, f"Política fraca ou permissiva: '{value.strip()}'"


def calculate_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    return "F"


def audit_url(target_url: str, timeout: int = 10, user_agent: str = None):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
        
    parsed = urlparse(target_url)
    is_https = parsed.scheme == "https"
    
    headers = {
        "User-Agent": user_agent or "InfoSec-Headers-Auditor/1.0 (+https://github.com/rafaelsoje/infosec-audit-tools)"
    }
    
    try:
        response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        return {"error": f"Falha de certificado SSL/TLS ao conectar em {target_url}: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Falha ao conectar no host {target_url}: {e}"}
    except requests.exceptions.Timeout:
        return {"error": f"Conexão expirou (timeout de {timeout}s) para {target_url}"}
    except Exception as e:
        return {"error": f"Erro inesperado: {e}"}
        
    resp_headers = response.headers
    final_url = response.url
    status_code = response.status_code
    
    results = {
        "target": target_url,
        "final_url": final_url,
        "status_code": status_code,
        "is_https": final_url.startswith("https://"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "headers_found": {},
        "missing_headers": [],
        "leaked_headers": {},
        "score": 0,
        "grade": "F",
        "recommendations": [],
    }
    
    current_score = 0
    max_possible_score = sum(cfg["weight"] for cfg in SECURITY_HEADERS.values())
    
    for header, cfg in SECURITY_HEADERS.items():
        if header in resp_headers:
            raw_value = resp_headers[header]
            is_valid, detail = cfg["validate"](raw_value)
            
            if is_valid:
                earned = cfg["weight"]
                status = "PASS"
            else:
                earned = cfg["weight"] // 2
                status = "WARN"
                results["recommendations"].append(f"Ajustar '{header}': {detail}")
                
            current_score += earned
            results["headers_found"][header] = {
                "value": raw_value,
                "status": status,
                "detail": detail,
                "points": earned,
            }
        else:
            results["missing_headers"].append(header)
            if cfg["required"]:
                results["recommendations"].append(f"Implementar cabeçalho obrigatório '{header}': {cfg['description']}")
                
    # Penalizar cabeçalhos que vazam informações
    leak_penalty = 0
    for leak_hdr in INFORMATION_LEAK_HEADERS:
        if leak_hdr in resp_headers:
            val = resp_headers[leak_hdr]
            results["leaked_headers"][leak_hdr] = val
            leak_penalty += 5
            results["recommendations"].append(f"Remover ou mascarar cabeçalho '{leak_hdr}: {val}' para evitar fingerprinting de servidor")
            
    final_score = max(0, min(100, int((current_score / max_possible_score) * 100) - leak_penalty))
    results["score"] = final_score
    results["grade"] = calculate_grade(final_score)
    
    return results


def print_cli_report(results: dict):
    print("=" * 75)
    print(" Auditoria de Segurança: Cabeçalhos HTTP Defensivos (OWASP)")
    print("=" * 75)
    print(f" Alvo Analisado:    {results['target']}")
    print(f" URL Final:         {results['final_url']} (HTTP {results['status_code']})")
    print(f" Protocolo Seguro:  {'Sim (HTTPS)' if results['is_https'] else 'Não (HTTP Não Criptografado)'}")
    print(f" Data da Avaliação: {results['timestamp']}")
    print("=" * 75)
    
    print("\n[+] Cabeçalhos Defensivos Analisados:\n")
    for hdr, data in results["headers_found"].items():
        tag = "[OK]  " if data["status"] == "PASS" else "[WARN]"
        print(f"  {tag} {hdr}:")
        print(f"         Valor:   {data['value']}")
        print(f"         Análise: {data['detail']}")
        
    for hdr in results["missing_headers"]:
        print(f"  [MISS] {hdr}: Ausente")
        
    if results["leaked_headers"]:
        print("\n[!] Exposição de Metadados de Servidor (Information Disclosure):")
        for hdr, val in results["leaked_headers"].items():
            print(f"  [ALERTA] {hdr}: {val}")
    else:
        print("\n[+] Exposição de Servidor: Nenhum cabeçalho de fingerprint detectado.")
        
    print("\n" + "-" * 75)
    print(f" Pontuação Técnica: {results['score']}/100 | Nota de Conformidade: {results['grade']}")
    print("-" * 75)
    
    if results["recommendations"]:
        print("\n[*] Recomendações Prioritárias de Remediação:")
        for idx, rec in enumerate(results["recommendations"], 1):
            print(f"  {idx}. {rec}")
            
    print("\n" + "=" * 75)


def main():
    parser = argparse.ArgumentParser(
        description="Auditor defensivo de cabeçalhos HTTP baseado no OWASP Secure Headers Project."
    )
    parser.add_argument("target", help="URL ou domínio alvo para auditoria (ex: https://exemplo.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Tempo limite de conexão em segundos (padrão: 10)")
    parser.add_argument("--json", action="store_true", help="Emitir saída estruturada em formato JSON")
    parser.add_argument("-o", "--output", help="Caminho do arquivo para salvar o relatório")
    
    args = parser.parse_args()
    
    results = audit_url(args.target, timeout=args.timeout)
    
    if "error" in results:
        print(f"[ERRO] {results['error']}", file=sys.stderr)
        sys.exit(1)
        
    if args.json:
        json_output = json.dumps(results, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] Relatório JSON salvo com sucesso em: {args.output}")
        else:
            print(json_output)
    else:
        print_cli_report(results)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json.dumps(results, indent=2, ensure_ascii=False))
            print(f"[+] Relatório bruto salvo em: {args.output}")


if __name__ == "__main__":
    main()
