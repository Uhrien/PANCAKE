# lib/utils.py

import socket

def ip_sort_key(ip):
    """Funzione per convertire un indirizzo IP in un formato ordinabile."""
    return list(map(int, ip.split('.')))

def reverse_dns(ip):
    """Esegue la risoluzione DNS inversa per un dato IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        print(f"[INFO] Hostname per {ip} trovato: {hostname}")
        return hostname
    except socket.herror:
        print(f"[WARN] Hostname per {ip} non disponibile.")
        return "Non disponibile"
