# lib/device_analysis.py

import socket
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from mac_vendor_lookup import MacLookup
import requests
import ssl
from .utils import reverse_dns, ip_sort_key

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_nmap(ip, ports='1-1024'):
    """Scansiona le porte e esegue il fingerprinting del sistema operativo per un dato IP."""
    nm = nmap.PortScanner()
    try:
        print(f"[INFO] Inizio scansione Nmap per {ip}")
        # Scansione delle porte, OS detection avanzata e version detection
        nm.scan(ip, ports, arguments='-O --osscan-guess -sS -sV --version-intensity 5 -T4 --min-rate=1000')
        if ip in nm.all_hosts() and nm[ip].state() == "up":
            print(f"[INFO] Scansione Nmap per {ip} completata.")
            return nm[ip]
    except Exception as e:
        print(f"[ERROR] Errore nella scansione di nmap per {ip}: {e}")
    return None

def grab_http_banner(ip, port):
    """Effettua il banner grabbing HTTP/HTTPS su una porta specifica di un IP."""
    try:
        if port == 443 or port == 8443:
            url = f"https://{ip}:{port}"
        else:
            url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=3, verify=False)
        server_header = response.headers.get('Server', 'Non disponibile')
        print(f"[INFO] Server header per {ip}:{port} -> {server_header}")
        return server_header
    except Exception:
        print(f"[WARN] HTTP banner grabbing fallito per {ip}:{port}")
    return None

def get_ssl_certificate(ip, port):
    """Recupera il certificato SSL/TLS da una porta specifica di un IP."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                print(f"[INFO] Certificato SSL ricevuto da {ip}:{port}")
                return cert
    except Exception:
        print(f"[WARN] Recupero certificato SSL fallito per {ip}:{port}")
    return None

def grab_banner(ip, port):
    """Effettua il banner grabbing su una porta specifica di un IP."""
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024)
            if banner:
                banner_decoded = banner.decode(errors='ignore').strip()
                print(f"[INFO] Banner ricevuto da {ip}:{port} -> {banner_decoded}")
                return banner_decoded
    except Exception:
        print(f"[WARN] Banner grabbing fallito per {ip}:{port}")
    return None

def gather_info(device, ports='1-1024', verbosity=False):
    """Raccoglie informazioni dettagliate su un dato IP."""
    ip = device['IP']
    mac = device.get('MAC', 'Non disponibile')
    info = {'IP': ip, 'MAC': mac}
    
    # Rilevamento del produttore tramite indirizzo MAC
    if mac != 'Non disponibile':
        try:
            vendor = MacLookup().lookup(mac)
            print(f"[INFO] Vendor per {mac}: {vendor}")
        except Exception:
            vendor = "Non disponibile"
        info['Vendor'] = vendor
    else:
        info['Vendor'] = "Non disponibile"
    
    # Risoluzione DNS inversa
    hostname = reverse_dns(ip)
    info['Hostname'] = hostname
    
    # Scansione delle porte e fingerprinting del sistema operativo
    host_info = scan_nmap(ip, ports)
    if host_info:
        # Porte aperte con informazioni sul servizio
        ports_info = {}
        for proto in host_info.all_protocols():
            lport = host_info[proto].keys()
            for port in lport:
                service = host_info[proto][port].get('product', 'N/A')
                version = host_info[proto][port].get('version', 'N/A')
                ports_info[port] = {
                    'state': host_info[proto][port]['state'],
                    'service': service,
                    'version': version
                }
        info['Ports'] = ports_info
        if verbosity:
            print(f"[INFO] Porte aperte per {ip}: {ports_info}")
        
        # Sistema operativo
        os_info = host_info.get('osmatch', [])
        if os_info:
            os_details = []
            for os_match in os_info:
                os_details.append({
                    "Name": os_match.get('name', 'N/A'),
                    "Accuracy": os_match.get('accuracy', 'N/A'),
                    "OS Class": os_match.get('osclass', [])
                })
            info['OS'] = os_details
            if verbosity:
                print(f"[INFO] Informazioni OS per {ip}: {os_details}")
        else:
            info['OS'] = "Non determinato"
            if verbosity:
                print(f"[WARN] Informazioni OS per {ip} non determinate.")
    else:
        info['Ports'] = {}
        info['OS'] = "Non determinato"
        if verbosity:
            print(f"[WARN] Nessuna informazione sulle porte per {ip}.")
    
    # Banner grabbing su porte comuni estese
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 119, 135, 139, 143, 443, 445, 993,
        995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000
    ]
    banners = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {}
        for port in common_ports:
            if port in info['Ports']:
                if port in [80, 443, 8080, 8443]:
                    future = executor.submit(grab_http_banner, ip, port)
                else:
                    future = executor.submit(grab_banner, ip, port)
                future_to_port[future] = port
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                banner = future.result()
                if banner:
                    banners[port] = banner
            except Exception as e:
                print(f"[ERROR] Errore nel banner grabbing per {ip}:{port} - {e}")
    
    if banners:
        info['Banners'] = banners
        if verbosity:
            print(f"[INFO] Banners per {ip}: {banners}")
    else:
        info['Banners'] = {}
        if verbosity:
            print(f"[WARN] Nessun banner trovato per {ip}.")
    
    # Recupero del certificato SSL/TLS
    ssl_info = {}
    for port in [443, 8443]:
        if port in info['Ports']:
            cert = get_ssl_certificate(ip, port)
            if cert:
                ssl_info[port] = cert
    if ssl_info:
        info['SSL_Certificate'] = ssl_info
    
    return info

def print_summary(results, output_file='network_summary.json'):
    """Salva il riepilogo delle informazioni raccolte in un file JSON."""
    # Ordina i risultati in base all'indirizzo IP
    results_sorted = sorted(results, key=lambda x: ip_sort_key(x['IP']))
    
    # Salva il riepilogo in un file JSON
    absolute_output_path = os.path.abspath(output_file)
    print(f"[DEBUG] Salvando riepilogo in: {absolute_output_path}")
    try:
        with open(absolute_output_path, 'w') as f:
            json.dump(results_sorted, f, indent=4)
        print(f"\n[INFO] Riepilogo delle informazioni raccolte salvato in {absolute_output_path}")
    except Exception as e:
        print(f"[ERROR] Errore nel salvare il riepilogo: {e}")

def analyze_devices(max_threads_analysis=30, output_file='network_summary.json', active_devices=None, ports='1-1024', verbosity=False):
    """Funzione principale per analizzare i dispositivi nella rete locale."""
    if not active_devices:
        raise ValueError("La lista degli IP attivi è necessaria.")
    
    if verbosity:
        print("\n[INFO] Inizio la scansione dettagliata dei dispositivi...\n")
    
    results = []
    with ThreadPoolExecutor(max_workers=max_threads_analysis) as executor:
        future_to_device = {executor.submit(gather_info, device, ports, verbosity): device for device in active_devices}
        for future in as_completed(future_to_device):
            device = future_to_device[future]
            ip = device['IP']
            try:
                info = future.result()
                results.append(info)
                if verbosity:
                    print(f"[INFO] Informazioni raccolte per {ip}")
            except Exception as e:
                print(f"[ERROR] Errore nell'elaborazione di {ip}: {e}")
    
    # Salva e stampa il riepilogo
    print_summary(results, output_file)
    return results
