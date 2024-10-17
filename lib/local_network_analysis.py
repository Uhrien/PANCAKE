# lib/local_network_analysis.py

import socket
import nmap
import os
from .utils import ip_sort_key

def get_local_ip():
    """Ottiene l'indirizzo IP locale."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Indirizzo IP pubblico noto per determinare l'IP locale
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
        print(f"[INFO] Indirizzo IP locale rilevato: {IP}")
    except Exception:
        IP = '127.0.0.1'
        print("[WARN] Impossibile determinare l'indirizzo IP locale. Impostato a 127.0.0.1")
    finally:
        s.close()
    return IP

def get_ip_prefix(ip=None):
    """Determina automaticamente il prefisso IP della rete locale."""
    if not ip:
        ip = get_local_ip()
    if ip == '127.0.0.1':
        raise Exception("Impossibile determinare l'indirizzo IP locale.")
    # Assume /24 subnet
    netmask = ip.rsplit('.', 1)[0] + '.0/24'
    print(f"[INFO] Prefisso IP determinato: {netmask}")
    return netmask

def get_active_ips(ip_prefix='192.168.1.0/24', output_file='active_ips.txt'):
    """Utilizza Nmap per rilevare gli IP attivi nella rete locale."""
    nm = nmap.PortScanner()
    try:
        target = ip_prefix
        print(f"[INFO] Inizio scansione Nmap per host discovery su {target}")
        # Scansione rapida con min-rate per velocizzare
        nm.scan(hosts=target, arguments='-sn -T4 --min-rate=1000')

        active_devices = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                mac = nm[host]['addresses'].get('mac', 'Non disponibile')
                active_devices.append({'IP': host, 'MAC': mac})
                print(f"[INFO] IP attivo trovato: {host}, MAC: {mac}")

        print(f"[INFO] Scansione completata. Numero di IP attivi trovati: {len(active_devices)}")

        # Ordina gli IP attivi
        active_devices_sorted = sorted(active_devices, key=lambda x: ip_sort_key(x['IP']))

        # Salva gli IP attivi in un file
        absolute_output_path = os.path.abspath(output_file)
        print(f"[DEBUG] Salvando IP attivi in: {absolute_output_path}")
        with open(absolute_output_path, 'w') as f:
            for device in active_devices_sorted:
                f.write(f"{device['IP']},{device['MAC']}\n")
        print(f"[INFO] IP attivi salvati in {absolute_output_path}")

        return active_devices_sorted
    except Exception as e:
        print(f"[ERROR] Errore durante la scansione degli IP attivi: {e}")
        return []
