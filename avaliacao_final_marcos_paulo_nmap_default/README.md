# Avaliacao Final - Marcos Paulo (Nmap como padrão)

Projeto pronto para rodar com **Nmap como scanner padrão** (rápido), e opção de habilitar **Nikto** e **ZAP** pela interface.

## Requisitos
- Ubuntu 22.04+
- Python 3.10+
- Ferramentas: `nmap` (obrigatório), `nikto` e `zaproxy` (opcionais).

## Instalação
```bash
cd avaliacao_final_marcos_paulo_nmap_default
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo apt update
sudo apt install -y nmap        # obrigatório
sudo apt install -y nikto whatweb   # opcional (para usar Nikto)
snap list | grep zaproxy || sudo snap install zaproxy  # opcional (para usar ZAP Quick Scan)
# (Opcional) Docker para usar ZAP Baseline:
# docker pull owasp/zap2docker-stable
```

## Uso
```bash
python app.py
# Acesse http://127.0.0.1:5000
# Por padrão, só o Nmap está habilitado; marque os outros se quiser.
```
