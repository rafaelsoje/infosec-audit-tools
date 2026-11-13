#!/usr/bin/env python3
"""
Email Security, Anti-Spoofing & DMARC/SPF/DKIM Defensive Auditor
Autor: Rafael Soje (https://github.com/rafaelsoje)
Especialização: Segurança da Informação & DevSecOps

Auditor passivo de postura de segurança de e-mail e políticas anti-spoofing via DNS:
- Validação de SPF (RFC 7208): mecanismo 'all', limite de lookups DNS e duplicidade
- Análise de DMARC (RFC 7489): política ('p='), subdomínios ('sp='), percentual ('pct='), alinhamento e relatórios (rua/ruf)
- Descoberta e validação de chaves DKIM (RFC 6376) via seletores conhecidos ou customizados
- Verificação de registros MX e detecção de risco de personificação de marca (Domain Spoofing Risk)
- Cálculo de pontuação técnica (0 a 100) e nota de conformidade de A+ a F
- Saída amigável em terminal e suporte a exportação estruturada em JSON
"""

import argparse
from datetime import datetime, timezone
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("[ERRO] Biblioteca 'requests' não encontrada. Instale via: pip install requests", file=sys.stderr)
    sys.exit(1)


# Provedores de DNS-over-HTTPS (DoH) para consultas resilientes sem dependências de sistema
DOH_ENDPOINTS = [
    {
        "name": "Cloudflare",
        "url": "https://cloudflare-dns.com/dns-query",
        "headers": {"accept": "application/dns-json"},
        "params": lambda name, rtype: {"name": name, "type": rtype},
    },
    {
        "name": "Google",
        "url": "https://dns.google/resolve",
        "headers": {"accept": "application/json"},
        "params": lambda name, rtype: {"name": name, "type": rtype},
    },
]

# Seletores comuns para descoberta passiva de chaves DKIM
COMMON_DKIM_SELECTORS = [
    "google",
    "default",
    "k1",
    "mail",
    "s1",
    "s2",
    "selector1",
    "s2048",
    "scph",
    "dkim",
    "mandrill",
    "smtp",
    "postmark",
    "sendgrid",
    "zoho",
    "protonmail",
    "hubspot",
]


def clean_domain(domain: str) -> str:
    """Normaliza o domínio removendo protocolos, caminhos e espaços."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    return domain.strip(".")


def query_doh(name: str, rtype: str = "TXT", timeout: int = 8) -> List[str]:
    """Consulta registros DNS via DNS-over-HTTPS com fallback entre provedores."""
    for provider in DOH_ENDPOINTS:
        try:
            params = provider["params"](name, rtype)
            response = requests.get(
                provider["url"],
                headers=provider["headers"],
                params=params,
                timeout=timeout,
            )
            if response.status_code == 200:
                data = response.json()
                answers = data.get("Answer", [])
                results = []
                for ans in answers:
                    # O Cloudflare/Google retorna o tipo correspondente (16 para TXT, 15 para MX)
                    val = ans.get("data", "").strip('"')
                    # Remove aspas concatenadas em respostas TXT divididas
                    val = re.sub(r'"\s+"', "", val)
                    if val:
                        results.append(val)
                return results
        except requests.RequestException:
            continue
    return []


def audit_mx(domain: str, timeout: int = 8) -> Dict[str, Any]:
    """Verifica a presença de registros MX configurados no domínio."""
    records = query_doh(domain, rtype="MX", timeout=timeout)
    return {
        "has_mx": len(records) > 0,
        "count": len(records),
        "records": records,
    }


def audit_spf(domain: str, timeout: int = 8) -> Dict[str, Any]:
    """Audita a configuração do Sender Policy Framework (SPF) conforme RFC 7208."""
    txt_records = query_doh(domain, rtype="TXT", timeout=timeout)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    res: Dict[str, Any] = {
        "present": False,
        "multiple_records": False,
        "raw_record": None,
        "all_mechanism": None,
        "qualifier_status": "FAIL",
        "lookup_count": 0,
        "exceeds_lookup_limit": False,
        "uses_ptr": False,
        "status": "FAIL",
        "score": 0,
        "detail": "",
        "recommendations": [],
    }

    if not spf_records:
        res["detail"] = "Registro SPF não encontrado. Qualquer remetente pode disparar e-mails forjando este domínio."
        res["recommendations"].append("Crie um registro TXT com 'v=spf1 ... -all' autorizando apenas servidores legítimos.")
        return res

    if len(spf_records) > 1:
        res["present"] = True
        res["multiple_records"] = True
        res["raw_record"] = " | ".join(spf_records)
        res["status"] = "FAIL"
        res["detail"] = f"Múltiplos registros SPF detectados ({len(spf_records)}). A RFC 7208 invalida o SPF caso haja mais de um registro."
        res["recommendations"].append("Consolide todos os registros SPF em um único registro TXT.")
        return res

    raw = spf_records[0]
    res["present"] = True
    res["raw_record"] = raw

    # Identificar mecanismo 'all'
    all_match = re.search(r"([+\-~?])?all\b", raw)
    if all_match:
        qualifier = all_match.group(1) or "+"
        res["all_mechanism"] = f"{qualifier}all"
        if qualifier == "-":
            res["qualifier_status"] = "STRICT_HARDFAIL"
            res["score"] += 35
            res["detail"] = "Política estrita (-all / HardFail). Servidores receptores rejeitarão remetentes não autorizados."
        elif qualifier == "~":
            res["qualifier_status"] = "SOFTFAIL"
            res["score"] += 25
            res["detail"] = "Política SoftFail (~all). Aceitável se combinado com DMARC com política de rejeição (p=reject)."
        elif qualifier == "?":
            res["qualifier_status"] = "NEUTRAL"
            res["score"] += 10
            res["detail"] = "Política Neutra (?all). Não protege contra falsificação; o domínio é considerado desprotegido."
            res["recommendations"].append("Altere o mecanismo final do SPF de '?all' para '-all' (ou '~all' com DMARC).")
        elif qualifier == "+":
            res["qualifier_status"] = "PASS_ALL"
            res["score"] = 0
            res["detail"] = "CRÍTICO: '+all' autoriza explicitamente qualquer IP da Internet a enviar e-mails em nome do domínio."
            res["recommendations"].append("Remova imediatamente '+all' e configure '-all'.")
    else:
        res["qualifier_status"] = "MISSING_ALL"
        res["detail"] = "Registro SPF não define um mecanismo final 'all'. Comportamento padrão é neutro."
        res["recommendations"].append("Adicione '-all' ao final da diretiva SPF.")

    # Contagem de lookups DNS (RFC 7208 estipula limite máximo de 10)
    tokens = raw.split()
    lookup_mechanisms = ["include:", "a", "mx", "ptr", "exists", "redirect="]
    lookup_count = 0
    for token in tokens[1:]:
        tok_lower = token.lower()
        if any(tok_lower.startswith(m) or tok_lower == m for m in lookup_mechanisms):
            lookup_count += 1
        if tok_lower.startswith("ptr") or tok_lower == "ptr":
            res["uses_ptr"] = True

    res["lookup_count"] = lookup_count
    if lookup_count > 10:
        res["exceeds_lookup_limit"] = True
        res["score"] = max(0, res["score"] - 15)
        res["recommendations"].append(f"Reduza o número de lookups DNS no SPF (atualmente {lookup_count}). O limite da RFC 7208 é 10 lookups.")

    if res["uses_ptr"]:
        res["recommendations"].append("Evite o mecanismo 'ptr' no SPF; ele é obsoleto e consome excessivas consultas DNS reversas.")

    res["status"] = "PASS" if res["score"] >= 25 else "WARN"
    return res


def audit_dmarc(domain: str, timeout: int = 8) -> Dict[str, Any]:
    """Audita a configuração de DMARC conforme RFC 7489."""
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = query_doh(dmarc_domain, rtype="TXT", timeout=timeout)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    res: Dict[str, Any] = {
        "present": False,
        "raw_record": None,
        "policy": None,
        "subdomain_policy": None,
        "percentage": 100,
        "rua": None,
        "ruf": None,
        "adkim": "r",
        "aspf": "r",
        "status": "FAIL",
        "score": 0,
        "detail": "",
        "recommendations": [],
    }

    if not dmarc_records:
        res["detail"] = "Registro DMARC não encontrado. Provedores receptores não sabem como tratar mensagens forjadas."
        res["recommendations"].append("Crie o registro TXT em '_dmarc." + domain + "' com no mínimo 'v=DMARC1; p=quarantine; rua=mailto:...'")
        return res

    raw = dmarc_records[0]
    res["present"] = True
    res["raw_record"] = raw

    # Extração de tags DMARC
    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "").lower()
    res["policy"] = policy
    res["subdomain_policy"] = tags.get("sp", policy).lower()
    res["rua"] = tags.get("rua")
    res["ruf"] = tags.get("ruf")
    res["adkim"] = tags.get("adkim", "r").lower()
    res["aspf"] = tags.get("aspf", "r").lower()

    # Validação do percentual de aplicação (pct)
    try:
        pct = int(tags.get("pct", "100"))
        res["percentage"] = pct
    except ValueError:
        pct = 100
        res["percentage"] = 100

    if policy == "reject":
        if pct == 100:
            res["score"] += 45
            res["detail"] = "Política DMARC máxima ('p=reject' com 100%). Mensagens não alinhadas serão rejeitadas."
        else:
            res["score"] += 35
            res["detail"] = f"Política 'p=reject', mas com percentual parcial ({pct}%). Provedores rejeitarão apenas parte do tráfego forjado."
            res["recommendations"].append(f"Eleve 'pct={pct}' para 'pct=100' para atingir proteção total.")
    elif policy == "quarantine":
        if pct == 100:
            res["score"] += 30
            res["detail"] = "Política de Quarentena ('p=quarantine'). Mensagens forjadas serão direcionadas à pasta de Spam."
        else:
            res["score"] += 20
            res["detail"] = f"Política 'p=quarantine' com aplicação parcial ({pct}%)."
            res["recommendations"].append("Ajuste a política para 100% de quarentena e planeje a transição para 'p=reject'.")
    elif policy == "none":
        res["score"] += 10
        res["detail"] = "Modo de Monitoramento ('p=none'). NÃO protege contra spoofing; serve apenas para coletar relatórios."
        res["recommendations"].append("Transicione a política DMARC de 'p=none' para 'p=quarantine' e posteriormente 'p=reject'.")
    else:
        res["detail"] = f"Política DMARC inválida ou desconhecida: '{policy}'."
        res["recommendations"].append("Defina 'p=reject' ou 'p=quarantine' no registro DMARC.")

    # Relatórios de telemetria RUA
    if res["rua"]:
        res["score"] += 5
    else:
        res["recommendations"].append("Configure um endereço de e-mail para receber relatórios agregados ('rua=mailto:...').")

    res["status"] = "PASS" if res["score"] >= 30 else "WARN"
    return res


def audit_dkim(domain: str, custom_selector: Optional[str] = None, timeout: int = 8) -> Dict[str, Any]:
    """Audita a presença de chaves públicas DKIM via seletores."""
    selectors_to_check = []
    if custom_selector:
        selectors_to_check.append(custom_selector)
    selectors_to_check.extend([s for s in COMMON_DKIM_SELECTORS if s != custom_selector])

    res: Dict[str, Any] = {
        "present": False,
        "selectors_found": [],
        "records": {},
        "status": "WARN",
        "score": 0,
        "detail": "",
        "recommendations": [],
    }

    for selector in selectors_to_check:
        dkim_target = f"{selector}._domainkey.{domain}"
        txts = query_doh(dkim_target, rtype="TXT", timeout=timeout)
        dkim_txts = [t for t in txts if "v=dkim1" in t.lower() or "p=" in t.lower()]
        if dkim_txts:
            res["present"] = True
            res["selectors_found"].append(selector)
            res["records"][selector] = dkim_txts[0]

    if res["present"]:
        res["status"] = "PASS"
        res["score"] = 15
        selectors_str = ", ".join(res["selectors_found"])
        res["detail"] = f"Chave(s) pública(s) DKIM descoberta(s) para o(s) seletor(es): {selectors_str}."
    else:
        res["status"] = "WARN"
        res["detail"] = "Nenhum seletor público DKIM comum foi descoberto via busca passiva."
        res["recommendations"].append("Garanta que o envio de e-mails assine mensagens com DKIM e informe o seletor via '--selector <nome>'.")

    return res


def calculate_spoofing_risk(spf: Dict[str, Any], dmarc: Dict[str, Any], mx: Dict[str, Any]) -> Tuple[str, str]:
    """Calcula o risco de personificação de marca (Domain Spoofing Vulnerability)."""
    dmarc_policy = dmarc.get("policy")
    dmarc_present = dmarc.get("present", False)
    dmarc_pct = dmarc.get("percentage", 100)
    spf_qualifier = spf.get("all_mechanism")
    spf_present = spf.get("present", False)

    if not dmarc_present and (not spf_present or spf_qualifier in ["+all", "?all", None]):
        return (
            "CRÍTICO",
            "VULNERÁVEL A SPOOFING TOTAL: Qualquer pessoa na Internet pode enviar e-mails forjando este domínio sem rejeição.",
        )

    if dmarc_policy == "none" or not dmarc_present:
        return (
            "ALTO",
            "SUSCETÍVEL A SPOOFING: A política DMARC é inexistente ou em modo observação (p=none). Ataques de phishing podem alcançar caixas de entrada.",
        )

    if dmarc_policy == "quarantine" or dmarc_pct < 100:
        return (
            "MÉDIO",
            "PROTEÇÃO PARCIAL: E-mails forjados tendem a ser entregues na pasta de Spam ou possuem mitigação incompleta (pct < 100%).",
        )

    if dmarc_policy == "reject" and dmarc_pct == 100:
        return (
            "BAIXO (SEGURO)",
            "PROTEGIDO CONTRA SPOOFING: Política 'p=reject' ativa com 100% de aplicação. Servidores receptores descartam e-mails não autorizados.",
        )

    return ("INDEFINIDO", "Configuração requer análise manual aprofundada.")


def calculate_grade(score: int) -> str:
    """Converte a pontuação técnica (0-100) em nota de conformidade."""
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def audit_domain_email_security(domain: str, selector: Optional[str] = None, timeout: int = 8) -> Dict[str, Any]:
    """Orquestra a auditoria completa de segurança de e-mail do domínio."""
    clean = clean_domain(domain)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    mx_res = audit_mx(clean, timeout=timeout)
    spf_res = audit_spf(clean, timeout=timeout)
    dmarc_res = audit_dmarc(clean, timeout=timeout)
    dkim_res = audit_dkim(clean, custom_selector=selector, timeout=timeout)

    total_score = min(100, spf_res["score"] + dmarc_res["score"] + dkim_res["score"])
    grade = calculate_grade(total_score)
    risk_level, risk_desc = calculate_spoofing_risk(spf_res, dmarc_res, mx_res)

    all_recommendations = []
    all_recommendations.extend(spf_res.get("recommendations", []))
    all_recommendations.extend(dmarc_res.get("recommendations", []))
    all_recommendations.extend(dkim_res.get("recommendations", []))

    return {
        "target_domain": clean,
        "timestamp": timestamp,
        "score": total_score,
        "grade": grade,
        "spoofing_risk": {
            "level": risk_level,
            "description": risk_desc,
        },
        "mx": mx_res,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "dkim": dkim_res,
        "recommendations": all_recommendations,
    }


def print_cli_report(res: Dict[str, Any]):
    """Exibe o relatório formatado no terminal sem dependência de emojis."""
    print("=" * 78)
    print(" Auditoria de Segurança de E-mail: SPF, DMARC & Anti-Spoofing")
    print("=" * 78)
    print(f" Domínio Alvo:      {res['target_domain']}")
    print(f" Servidores MX:     {'Configurados (' + str(res['mx']['count']) + ' registros)' if res['mx']['has_mx'] else 'Nenhum registro MX detectado'}")
    print(f" Data da Avaliação: {res['timestamp']}")
    print("=" * 78)

    # 1. SPF
    spf = res["spf"]
    tag_spf = "[OK]  " if spf["status"] == "PASS" else "[WARN]" if spf["present"] else "[FAIL]"
    print(f"\n{tag_spf} Sender Policy Framework (SPF):")
    if spf["present"]:
        print(f"         Registro:     {spf['raw_record']}")
        print(f"         Mecanismo:    {spf['all_mechanism']} ({spf['qualifier_status']})")
        print(f"         Lookups DNS:  {spf['lookup_count']}/10")
        print(f"         Diagnóstico:  {spf['detail']}")
    else:
        print(f"         Diagnóstico:  {spf['detail']}")

    # 2. DMARC
    dmarc = res["dmarc"]
    tag_dmarc = "[OK]  " if dmarc["status"] == "PASS" else "[WARN]" if dmarc["present"] else "[FAIL]"
    print(f"\n{tag_dmarc} DMARC (Domain-based Message Authentication):")
    if dmarc["present"]:
        print(f"         Registro:     {dmarc['raw_record']}")
        print(f"         Política (p): {dmarc['policy']} | Subdomínios (sp): {dmarc['subdomain_policy']}")
        print(f"         Aplicação:    {dmarc['percentage']}%")
        print(f"         Relatórios:   rua={dmarc['rua'] or 'Ausente'}")
        print(f"         Diagnóstico:  {dmarc['detail']}")
    else:
        print(f"         Diagnóstico:  {dmarc['detail']}")

    # 3. DKIM
    dkim = res["dkim"]
    tag_dkim = "[OK]  " if dkim["status"] == "PASS" else "[INFO]"
    print(f"\n{tag_dkim} DomainKeys Identified Mail (DKIM):")
    if dkim["present"]:
        print(f"         Seletores:    {', '.join(dkim['selectors_found'])}")
        print(f"         Diagnóstico:  {dkim['detail']}")
    else:
        print(f"         Diagnóstico:  {dkim['detail']}")

    # Risco de Spoofing e Classificação
    risk = res["spoofing_risk"]
    print("\n" + "-" * 78)
    print(f" Nível de Risco de Spoofing: {risk['level']}")
    print(f" Avaliação de Defesa:        {risk['description']}")
    print("-" * 78)
    print(f" Pontuação Técnica: {res['score']}/100 | Nota de Conformidade: {res['grade']}")
    print("-" * 78)

    if res["recommendations"]:
        print("\n[*] Recomendações Prioritárias de Remediação:")
        for idx, rec in enumerate(res["recommendations"], 1):
            print(f"  {idx}. {rec}")

    print("\n" + "=" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="Auditor defensivo de segurança de e-mail e políticas anti-spoofing (SPF, DMARC e DKIM)."
    )
    parser.add_argument("domain", help="Domínio alvo para auditoria (ex: exemplo.com.br)")
    parser.add_argument("-s", "--selector", help="Seletor DKIM customizado para validação de chave pública")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Tempo limite para consultas DNS em segundos (padrão: 8)")
    parser.add_argument("--json", action="store_true", help="Emitir saída estruturada em formato JSON")
    parser.add_argument("-o", "--output", help="Caminho do arquivo para salvar o relatório")

    args = parser.parse_args()

    results = audit_domain_email_security(args.domain, selector=args.selector, timeout=args.timeout)

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
