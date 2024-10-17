# main.py

import argparse
import os
import sys
from lib.local_network_analysis import get_ip_prefix, get_active_ips
from lib.device_analysis import analyze_devices

def main():
    parser = argparse.ArgumentParser(description='Strumento completo di analisi della rete locale.')
    parser.add_argument('--prefix', type=str, help='Prefisso IP da utilizzare (es. 192.168.1.0/24)')
    parser.add_argument('--active_output', type=str, default='active_ips.txt', help='Nome del file di output per gli IP attivi.')
    parser.add_argument('--summary_output', type=str, default='network_summary.json', help='Nome del file di output per il riepilogo.')
    parser.add_argument('--threads', type=int, default=30, help='Numero massimo di thread per l\'analisi.')
    parser.add_argument('--ports', type=str, default='1-1024', help='Intervallo di porte da scansionare (es. 1-1024).')
    parser.add_argument('--verbosity', action='store_true', help='Aumenta il livello di verbosità dell\'output.')

    args = parser.parse_args()

    # Definisci la directory di output
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, 'output')

    # Crea la directory di output se non esiste
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            if args.verbosity:
                print(f"[INFO] Creata la directory di output: {output_dir}")
        except Exception as e:
            print(f"[ERROR] Impossibile creare la directory di output: {e}")
            sys.exit(1)
    else:
        if args.verbosity:
            print(f"[INFO] Directory di output esistente: {output_dir}")

    # Definisci i percorsi assoluti per i file di output
    active_output_path = os.path.join(output_dir, args.active_output)
    summary_output_path = os.path.join(output_dir, args.summary_output)

    # Debug: Stampa i percorsi assoluti se la verbosità è attiva
    if args.verbosity:
        print(f"[DEBUG] Percorso di output per dispositivi attivi: {active_output_path}")
        print(f"[DEBUG] Percorso di output per riepilogo: {summary_output_path}")

    try:
        # Ottieni il prefisso IP
        if args.prefix:
            ip_prefix = args.prefix
            if args.verbosity:
                print(f"[INFO] Prefisso IP fornito dall'utente: {ip_prefix}")
        else:
            ip_prefix = get_ip_prefix()
            if args.verbosity:
                print(f"[INFO] Prefisso IP rilevato automaticamente: {ip_prefix}")

        # Rileva dispositivi attivi (IP e MAC)
        active_devices = get_active_ips(ip_prefix=ip_prefix, output_file=active_output_path)

        if not active_devices:
            print("[WARN] Nessun dispositivo attivo trovato. Terminazione del programma.")
            sys.exit(0)

        # Analizza i dispositivi attivi
        analyze_devices(
            max_threads_analysis=args.threads,
            output_file=summary_output_path,
            active_devices=active_devices,
            ports=args.ports,
            verbosity=args.verbosity
        )

    except Exception as e:
        print(f"[ERROR] Errore nel programma principale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
