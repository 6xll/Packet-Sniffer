# Packet Sniffer Dev

Sniffer de pacotes com interface gráfica em Python (Tkinter + Scapy). Exibe apenas as interfaces de rede ativas ("up") no sistema Linux, tornando a captura de pacotes mais precisa e segura

### Funcionalidades

- Interface gráfica intuitiva com Tkinter
- Lista apenas interfaces de rede ativas no momento da seleção
- Captura e exibe detalhes de pacotes em tempo real (Ethernet, IP, TCP, UDP, etc.)
- Exibição do payload em texto ou hexadecimal
- Botões para iniciar, parar e limpar a captura
- Atualização dinâmica da lista de interfaces sem reiniciar o programa

## Instalação

### Clone o repositório:
```
git clone https://github.com/6xll/packet-sniffer.git
cd packet-sniffer
```
### Instale as dependências Python:
```
pip install -r requirements.txt
```
### No Linux, instale o Tkinter se necessário:
```
sudo apt-get install python3-tk
```
## Requisitos
- [Scapy](https://scapy.net/)
- [Python 3.7+](https://www.python.org/downloads/)
- [Tkinker](https://docs.python.org/3/library/tkinter.html) (padrão no Python, mas pode exigir python3-tk no Linux)
## Permissões
É necessário executar como root/admin para capturar pacotes em todas as interfaces de rede.
