# InfoSec Audit & Reconnaissance Tools 🛡️🔍

[![CI](https://github.com/rafaelsoje/infosec-audit-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelsoje/infosec-audit-tools/actions)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Security: InfoSec](https://img.shields.io/badge/Domain-Information%20Security-red)](https://rafaelsoje.com)
[![AsyncIO](https://img.shields.io/badge/Networking-AsyncIO%20%2F%20RDAP-green)](https://docs.python.org/3/library/asyncio.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Conjunto de utilitários em Python para reconhecimento de superfície de ataque, auditoria de cabeçalhos HTTP defensivos e validação de vulnerabilidades conhecidas em laboratório controlado.

Desenvolvido por **[Rafael Soje](https://rafaelsoje.com)** — Pós-graduado em Segurança da Informação e Engenheiro de Software Full Stack.

---

> [!CAUTION]
> **Aviso Ético e Legal (Disclaimer):**
> As ferramentas contidas neste repositório destinam-se estritamente a fins educacionais, exercícios de Blue Team / Red Team em ambientes controlados e testes de penetração autorizados pelo proprietário do ativo. O autor não se responsabiliza por qualquer utilização indevida ou ilegal.

---

## 📁 Estrutura do Repositório

```text
infosec-audit-tools/
├── recon/
│   ├── domain_availability_checker.py     # Reconhecimento assíncrono via RDAP e resolução DNS
│   ├── ssl_tls_security_auditor.py        # Auditoria passiva de SSL/TLS, Ciphers e certificados X.509
│   └── subdomain_recon_crtsh.py           # Descoberta passiva de subdomínios via CT Logs (crt.sh)
├── wordpress/
│   ├── really_simple_security_detector.py # Auditoria passiva de headers e detecção de versões
│   └── cve_2024_10924_poc.py              # PoC e guia de remediação para CVE-2024-10924
├── requirements.txt                       # Dependências do projeto (aiohttp, requests)
├── LICENSE                                # Licença MIT
└── README.md                              # Documentação e guias de execução
```

---

## 🚀 Instalação e Pré-requisitos

Recomenda-se a utilização de um ambiente virtual Python:

```bash
# Clonar o repositório
git clone https://github.com/rafaelsoje/infosec-audit-tools.git
cd infosec-audit-tools

# Criar e ativar o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

---

## 🛠️ Módulos e Exemplos de Uso

### 1. Reconhecimento de Superfície (`recon/`)

#### 🌐 `domain_availability_checker.py`
Utilitário de alto desempenho construído com `asyncio` e `aiohttp` para varredura e validação de disponibilidade de domínios em larga escala:
* Consulta serviços oficiais de **RDAP (Registration Data Access Protocol)**: Verisign (`.com`), Registro.br (`.com.br`) e `rdap.org`.
* Valida resolução DNS primária (`A`/`AAAA`) com controle de concorrência por semáforo (`asyncio.Semaphore`).
* Exportação direta para CSV para geração de relatórios de inteligência de marca e nomes de infraestrutura.

```bash
# Executar verificação a partir de lista de termos:
python3 recon/domain_availability_checker.py lista_nomes.txt --tlds com,com.br --concurrency 30 -o relatorio_disponiveis.csv

# Apenas exibir na saída padrão (terminal):
python3 recon/domain_availability_checker.py lista_nomes.txt --only-print
```

#### 🔒 `ssl_tls_security_auditor.py`
Auditor passivo de infraestrutura criptográfica SSL/TLS e certificados X.509:
* Conexão nativa via socket TLS sem dependências externas.
* Valida a versão do protocolo negociado (TLS 1.2 / TLS 1.3) e alerta sobre protocolos obsoletos.
* Inspeciona autoridade certificadora (CA), ciphers negociados e data exata de expiração com aviso de expiração iminente.
* Mapeia todos os **Subject Alternative Names (SANs)**, descobrindo subdomínios e domínios irmãos do alvo.

```bash
python3 recon/ssl_tls_security_auditor.py exemplo.com.br
```

#### 🌐 `subdomain_recon_crtsh.py`
Mapeador passivo de subdomínios utilizando Certificate Transparency (CT Logs):
* Consulta a base pública do `crt.sh` para descobrir ativos expostos sem tocar no alvo.
* Desduplica entradas, limpa wildcards (`*.`) e valida opcionalmente resolução DNS ativa (`--resolve`).
* Suporta exportação direta para CSV.

```bash
# Mapear e testar resolução DNS ativa:
python3 recon/subdomain_recon_crtsh.py exemplo.com.br --resolve -o subdominios.csv
```

---

### 2. Auditoria e Defesa Web (`wordpress/`)

#### 🛡️ `really_simple_security_detector.py`
Auditor passivo de postura de segurança web:
* Inspeciona cabeçalhos de proteção moderna:
  * `Strict-Transport-Security` (HSTS)
  * `Content-Security-Policy` (CSP)
  * `X-Content-Type-Options`
  * `X-Frame-Options`
  * `Permissions-Policy`
* Detecta assinaturas ativas do plugin no DOM/HTML.
* Audita o arquivo de changelog público (`readme.txt`) e emite alertas automáticos caso a versão instalada seja inferior a versões corrigidas contra vulnerabilidades conhecidas.

```bash
python3 wordpress/really_simple_security_detector.py https://exemplo.com.br
```

#### 🎯 `cve_2024_10924_poc.py`
Validador de conformidade e PoC laboratorial para a vulnerabilidade crítica **CVE-2024-10924** (CVSS 9.8 - *Authentication Bypass* no plugin *Really Simple Security* anterior à versão 9.1.2):
* Demonstra o impacto da ausência de checagem de nonce no endpoint `/reallysimplessl/v1/two_fa/skip_onboarding`.
* Acompanha recomendações de mitigação em nível de código e WAF (Cloudflare / Nginx).

```bash
# Executar em ambiente de laboratório controlado (ex: TryHackMe / HackTheBox / VM local):
python3 wordpress/cve_2024_10924_poc.py http://lab-alvo.local:8080 --user-id 1
```

---

## 🔒 Boas Práticas de Remediação

1. **Defesa em Profundidade**: Cabeçalhos de segurança HTTP devem ser sempre implementados na camada de borda (Cloudflare / Nginx / Apache), independentemente dos plugins da aplicação.
2. **Atualização Contínua**: Vulnerabilidades de alta severidade em CMS exigem patching ágil e monitoramento proativo de CVEs.
3. **Hardening de Endpoints**: Restringir endpoints de onboarding, autenticação e depuração via regras de WAF e controle de acesso baseado em IP.

---

## 👤 Autor

**Rafael Soje**
* **Website Oficial**: [rafaelsoje.com](https://rafaelsoje.com)
* **GitHub**: [@rafaelsoje](https://github.com/rafaelsoje)
* **Formação**: Pós-graduação em Segurança da Informação | Ciência da Computação

