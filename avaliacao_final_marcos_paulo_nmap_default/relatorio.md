# Avaliação Final – Marcos Paulo

## 1) Descrição do sistema e da arquitetura utilizada

**Nome do projeto:** *Avaliacao Final – Marcos Paulo*  
**Objetivo:** disponibilizar uma interface web simples para acionar varreduras de segurança com foco em **Nmap** (padrão), permitindo habilitar **Nikto** e **ZAP** sob demanda. Gera **relatório HTML/Markdown** e mantém **histórico** em SQLite.

**Arquitetura (alto nível):**

- **Frontend (Flask + Jinja2):** formulário com URL do alvo, checkboxes para escolher scanners, opções de Nmap (portas/“modo rápido”).
- **Orquestração (Python):**
  - Por padrão roda **Nmap** com `-sV -Pn --script ssl-enum-ciphers` (modo rápido: `-T4 --max-retries 1 --host-timeout` curto, portas `80,443`).
  - Opcional: **Nikto** (checagens de headers/SSL em tempo curto) e **ZAP** (Quick Scan/Baseline).
- **Persistência:** SQLite (`scanner.db`) + artefatos em `artifacts/<timestamp>_<alvo>/` (inclui `report.html`, `report.md`, `nmap_report.xml`, etc.).
- **Configuração:** `config.yaml` define timeouts, padrão de serviços habilitados e portas Nmap.

**Racional de concepção para B:**  
Priorizamos **Nmap** por ser mais rápido/estável e suficiente para evidenciar **exposição de serviços**, **banners de versão** e **políticas TLS** (via `ssl-enum-ciphers`). **ZAP/Nikto** foram mantidos opcionais para não comprometer a entrega por tempo.

---

## 2) Metodologia de testes

**Abordagem:** teste passivo/sem credenciais, focado em coleta de informações e identificação básica de serviços.

**Ferramentas (selecionáveis):**
- **Nmap (padrão):**
  - **Serviço/versão:** `-sV -Pn`
  - **Desempenho:** `-T4 --max-retries 1 --host-timeout 60–90s` (via “modo rápido”)
  - **TLS:** `--script ssl-enum-ciphers`
  - **Portas:** por padrão `80,443` (configurável pela UI)
- **Nikto (opcional):** plugins de `headers,ssl` e `-maxtime` para limitar duração.
- **ZAP (opcional):** Quick Scan/Baseline, sujeito a tempo maior; desabilitado por padrão no B.

**Fluxo:**
1. Selecionar **somente Nmap** (padrão) na UI.
2. Informar **URL do alvo** (o sistema extrai o *hostname* para o Nmap).
3. Definir **portas** (padrão `80,443`) e manter **Modo rápido**.
4. Executar e analisar:
   - `report.html` **consolidado**
   - `nmap_report.xml` (**evidência**)
5. Registrar achados e recomendações.

**Limitações (Conceito B):**
- Sem credenciais e sem brute-force.
- Sem testes intrusivos/ativações longas do ZAP.
- Foco em **exposição de portas/serviços**, **banners** e **política TLS**.

---

## 3) Resultados obtidos e exemplos de vulnerabilidades detectadas

A seguir, exemplos representativos coletados durante os testes. As evidências completas encontram-se nos artefatos gerados por execução.

### Alvos testados (amostra)

| Alvo                       | Portas/Serviços (exemplo)                                                       | Observações principais                 |
|---------------------------|----------------------------------------------------------------------------------|---------------------------------------|
| `https://example.com`     | 80/443 “open” (Akamai/AkamaiGHost); `ssl-enum-ciphers` → suites fortes          | Bom para sanity check/TLS             |
| `http://neverssl.com`     | 80 “open”; 443 “closed/filtered”                                                 | Útil p/ evidenciar ausência de HTTPS  |
| `http://testphp.vulnweb.com` | 80 open (nginx/1.19.0); 443 filtered                                         | Exposição de banner/versão; sem TLS ativo |
| `https://scanme.nmap.org` | Portas variam (ambiente oficial do Nmap p/ testes)                               | Usar poucas portas e modo leve        |
| `https://badssl.com` (+subs) | 443 open; variações de política/cert/tls por subdomínio                      | Útil p/ mapeamento TLS                |

### Exemplos de achados (como apareceram no relatório)

**Exposição de serviço/versão (A06 – Componentes desatualizados, potencial)**  
- **Host:** `http://testphp.vulnweb.com`  
- **Nmap:** `80/tcp open http nginx 1.19.0`  
- **Risco:** versão de servidor web aparente; versão antiga pode herdar CVEs.  
- **Evidência:** `artifacts/<timestamp>_http-testphp-vulnweb-com/nmap_report.xml`

**Ausência/filtragem de HTTPS (A02 – Falhas criptográficas, nível introdutório)**  
- **Host:** `http://testphp.vulnweb.com` / `http://neverssl.com`  
- **Nmap:** `443/tcp filtered` ou indisponível  
- **Risco:** tráfego em claro (HTTP) suscetível a interceptação/alteração.

**Política TLS forte (bom indicador)**  
- **Host:** `https://example.com`  
- **Nmap (ssl-enum-ciphers):** suites modernas (ex.: `TLS_ECDHE_*_GCM`, `CHACHA20`) e *least strength: A*  
- **Leitura:** não é uma falha; serve como exemplo de baseline saudável.

> Observação: no escopo B, **não** realizamos exploração ativa nem autenticação; o foco é **exposição** e **configuração**.

---

## 4) Sugestões de mitigação

### Reduzir a superfície exposta
- Fechar portas não utilizadas no **firewall/WAF**.
- Publicar apenas serviços estritamente necessários (**princípio do menor privilégio**).

### Ocultar banners de versão
- **Nginx/Apache:** mascarar/omitir versão e módulos nos headers/respostas.
- Monitorar **CVEs** de componentes expostos e **atualizar** periodicamente.

### Forçar HTTPS e reforçar política TLS
- Habilitar **HTTPS** e redirecionamento 301 de **HTTP→HTTPS**.
- Adotar **HSTS**, **TLS 1.2+**, remover suites **fracas/legadas**.
- Avaliar periodicamente com `ssl-enum-ciphers` (ou scanners TLS dedicados).

### Cabeçalhos de segurança (se usar Nikto/ZAP futuramente)
- **X-Frame-Options / Content-Security-Policy**, **X-Content-Type-Options**, **Referrer-Policy**.
- Cookies com `Secure` e `HttpOnly` (e `SameSite` quando aplicável).

### Ciclo de melhoria contínua
- Agendar varreduras rápidas (**Nmap**) após mudanças de infra.
- Incluir varreduras mais profundas (**ZAP/Nikto** completos) sob janela de manutenção.

---

## 5) Conclusão

Entreguei até o **Conceito B**: ferramenta funcional, execução prática priorizando **Nmap** (rápido), histórico e **relatório consolidado** em HTML/MD com evidências objetivas (portas/serviços/TLS). **ZAP/Nikto** permanecem opcionais e podem ser ativados quando houver janela de tempo maior — sem prejuízo à avaliação proposta.

---

## Anexos (artefatos gerados)

- `artifacts/<timestamp>_<alvo>/report.html` – relatório consolidado  
- `artifacts/<timestamp>_<alvo>/report.md` – relatório em Markdown  
- `artifacts/<...>/nmap_report.xml` – evidência bruta do Nmap  
- *(opcional, se habilitados)* `nikto_report.txt`, `zap_*report.*`