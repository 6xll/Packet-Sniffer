import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw, get_if_list
from datetime import datetime
import queue
import os

# --- Função para obter apenas interfaces "up" ---
def get_active_ifaces():
    active = []
    for iface in get_if_list():
        try:
            with open(f'/sys/class/net/{iface}/operstate') as f:
                if f.read().strip() == 'up':
                    active.append(iface)
        except Exception:
            pass
    return active

# --- Configurações de Performance ---
MAX_PACKETS = 1000
PACKET_QUEUE_SIZE = 100
UPDATE_INTERVAL = 100  # em milissegundos

# --- Inicialização da Janela Principal ---
root = tk.Tk()
root.title("Packet Sniffer - Dev Edition")
root.geometry("1000x800")

# --- Estado Global ---
captured_packets = []
packet_queue = queue.Queue(PACKET_QUEUE_SIZE)
sniffer_running = threading.Event()
auto_scroll_enabled = True
show_hex_payload = tk.BooleanVar(value=False, master=root)

def get_protocol_name(proto):
    names = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 58: "ICMPv6"}
    return names.get(proto, f"Proto {proto}")

def format_mac(mac):
    try:
        if isinstance(mac, str):
            return mac
        return ":".join(f"{b:02x}" for b in bytes(mac))
    except Exception:
        return str(mac)

def process_packet(pkt):
    try:
        summary = []
        if Ether in pkt:
            summary.append(f"{format_mac(pkt[Ether].src)} → {format_mac(pkt[Ether].dst)}")
        if IP in pkt:
            ip = pkt[IP]
            summary.append(f"{ip.src} → {ip.dst} | {get_protocol_name(ip.proto)}")
            if TCP in pkt:
                tcp = pkt[TCP]
                summary.append(f"Ports: {tcp.sport} → {tcp.dport}")
                summary.append(f"Flags: {tcp.sprintf('%TCP.flags%')}")
            elif UDP in pkt:
                udp = pkt[UDP]
                summary.append(f"Ports: {udp.sport} → {udp.dport}")
        summary.append(f"{len(pkt)} bytes")
        if not packet_queue.full():
            packet_queue.put((
                datetime.fromtimestamp(pkt.time).strftime('%H:%M:%S.%f')[:-3],
                " | ".join(summary),
                pkt
            ))
    except Exception as e:
        print(f"[!] Packet processing error: {e}")

def update_gui():
    global auto_scroll_enabled
    while not packet_queue.empty():
        ts, info, pkt = packet_queue.get()
        if len(captured_packets) >= MAX_PACKETS:
            captured_packets.pop(0)
            packet_list.delete(0)
        captured_packets.append(pkt)
        packet_list.insert(tk.END, f"[{ts}] {info}")
        if auto_scroll_enabled:
            packet_list.yview(tk.END)
    root.after(UPDATE_INTERVAL, update_gui)

def start_sniffer():
    iface = interface_combobox.get()
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    clear_button.config(state=tk.NORMAL)
    status_label.config(text="Status: Sniffing...", foreground="#4CAF50")
    sniffer_running.clear()
    def sniff_loop():
        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            stop_filter=lambda _: sniffer_running.is_set()
        )
    threading.Thread(target=sniff_loop, daemon=True).start()

def stop_sniffer():
    sniffer_running.set()
    stop_button.config(state=tk.DISABLED)
    start_button.config(state=tk.NORMAL)
    status_label.config(text="Status: Stopped", foreground="#F44336")

def clear_packets():
    captured_packets.clear()
    packet_list.delete(0, tk.END)
    details_text.config(state=tk.NORMAL)
    details_text.delete(1.0, tk.END)
    details_text.config(state=tk.DISABLED)

def show_details(event):
    try:
        selection = packet_list.curselection()
        if not selection:
            return  # Nenhum item selecionado, evita erro
        idx = selection[0]
        pkt = captured_packets[idx]
        details_text.config(state=tk.NORMAL)
        details_text.delete(1.0, tk.END)
        lines = []
        lines.append(f"=== Packet ===")
        lines.append(f"Timestamp: {datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        lines.append(f"Length: {len(pkt)} bytes\n")
        if Ether in pkt:
            eth = pkt[Ether]
            lines.extend([
                "-- Ethernet --",
                f"Src MAC: {format_mac(eth.src)}",
                f"Dst MAC: {format_mac(eth.dst)}",
                f"Type: 0x{eth.type:04x}\n"
            ])
        if IP in pkt:
            ip = pkt[IP]
            lines.extend([
                "-- IP --",
                f"Src: {ip.src}",
                f"Dst: {ip.dst}",
                f"Proto: {get_protocol_name(ip.proto)}",
                f"TTL: {ip.ttl}",
                f"ID: {ip.id}",
                f"Flags: DF={int(ip.flags.DF)} MF={int(ip.flags.MF)}\n"
            ])
        if TCP in pkt:
            tcp = pkt[TCP]
            lines.extend([
                "-- TCP --",
                f"Src Port: {tcp.sport}",
                f"Dst Port: {tcp.dport}",
                f"Seq: {tcp.seq} Ack: {tcp.ack}",
                f"Flags: {tcp.sprintf('%TCP.flags%')}",
                f"Window: {tcp.window} Checksum: 0x{tcp.chksum:04x}\n"
            ])
        elif UDP in pkt:
            udp = pkt[UDP]
            lines.extend([
                "-- UDP --",
                f"Src Port: {udp.sport}",
                f"Dst Port: {udp.dport}",
                f"Len: {udp.len} Checksum: 0x{udp.chksum:04x}\n"
            ])
        if Raw in pkt:
            payload = pkt[Raw].load
            lines.append("-- Payload --")
            if show_hex_payload.get():
                hexdata = payload[:100].hex(' ', 1)
                lines.append("Hex:")
                lines.append(hexdata + ("..." if len(payload) > 100 else ""))
            else:
                try:
                    decoded = payload.decode('utf-8', errors='replace')
                    printable = ''.join(c if c.isprintable() else '.' for c in decoded)
                    lines.append("Text:")
                    lines.append(printable[:200] + ("..." if len(decoded) > 200 else ""))
                except:
                    lines.append("[Error decoding payload]")
        details_text.insert(tk.END, "\n".join(lines))
        details_text.config(state=tk.DISABLED)
    except Exception as e:
        print(f"[!] Detail error: {e}")

def handle_scroll(event):
    global auto_scroll_enabled
    auto_scroll_enabled = (event.delta <= 0)

# --- Função para atualizar interfaces dinamicamente ---
def update_interfaces():
    interfaces = get_active_ifaces()
    interface_combobox['values'] = interfaces
    if interface_combobox.get() not in interfaces:
        interface_combobox.set(interfaces[0] if interfaces else "")

# --- Componentes da Interface Gráfica ---
style = ttk.Style()
style.theme_use('clam')
style.configure("TCombobox", background="white", foreground="black", font=("Segoe UI", 10))
style.configure("TButton", padding=6, relief="flat", width=10)
style.configure("Stop.TButton", background="#E74C3C")

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)
control_frame = ttk.Frame(main_frame)
control_frame.pack(fill=tk.X, pady=(0, 10))

ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5)
interface_combobox = ttk.Combobox(
    control_frame,
    values=get_active_ifaces(),
    width=15,
    postcommand=update_interfaces
)
interfaces = get_active_ifaces()
interface_combobox.set(interfaces[0] if interfaces else "")
interface_combobox.grid(row=0, column=1, padx=5)

start_button = ttk.Button(control_frame, text="Start", command=start_sniffer)
start_button.grid(row=0, column=2, padx=5)
stop_button = ttk.Button(control_frame, text="Stop", command=stop_sniffer, style="Stop.TButton", state=tk.DISABLED)
stop_button.grid(row=0, column=3, padx=5)
clear_button = ttk.Button(control_frame, text="Clear", command=clear_packets, state=tk.DISABLED)
clear_button.grid(row=0, column=4, padx=5)
status_label = ttk.Label(control_frame, text="Status: Idle", foreground="#F44336")
status_label.grid(row=0, column=5, padx=10)

packet_frame = ttk.LabelFrame(main_frame, text="Captured Packets", padding=10)
packet_frame.pack(fill=tk.BOTH, expand=True)
scrollbar = ttk.Scrollbar(packet_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
packet_list = tk.Listbox(packet_frame, yscrollcommand=scrollbar.set, font=("Consolas", 9), bg="#ECF0F1", fg="#2C3E50")
packet_list.pack(fill=tk.BOTH, expand=True)
packet_list.bind("<<ListboxSelect>>", show_details)
packet_list.bind("<MouseWheel>", handle_scroll)
scrollbar.config(command=packet_list.yview)

info_frame = ttk.LabelFrame(main_frame, text="Packet Details", padding=10)
info_frame.pack(fill=tk.BOTH, expand=True)
details_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, font=("Consolas", 9), bg="#ECF0F1", fg="#2C3E50")
details_text.pack(fill=tk.BOTH, expand=True)
details_text.config(state=tk.DISABLED)

toggle_frame = ttk.Frame(info_frame)
toggle_frame.pack(fill=tk.X, pady=5)
hex_checkbox = ttk.Checkbutton(toggle_frame, text="Show Hex Payload", variable=show_hex_payload, command=lambda: show_details(None))
hex_checkbox.pack(anchor='w')

footer = ttk.Label(root, text="Packet Sniffer Dev-edi", font=("Calibri", 8))
footer.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

# --- Inicia o loop da GUI ---
root.after(UPDATE_INTERVAL, update_gui)
root.mainloop()
