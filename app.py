# app.py

from flask import Flask, render_template, jsonify, request
import json
import os
import threading
from lib.local_network_analysis import get_ip_prefix, get_active_ips
from lib.device_analysis import analyze_devices

app = Flask(__name__)

# Variabili globali per monitorare lo stato della scansione
scan_in_progress = False
scan_progress = {'status': 'idle', 'percentage': 0, 'message': 'Inattivo'}
progress_lock = threading.Lock()

def perform_scan(output_file, summary_file, prefix=None, ports='1-1024', verbosity=False):
    global scan_in_progress
    global scan_progress
    scan_in_progress = True
    with progress_lock:
        scan_progress = {'status': 'Scanning', 'percentage': 10, 'message': 'Scansione degli IP attivi'}
    try:
        if prefix:
            ip_prefix = prefix
        else:
            ip_prefix = get_ip_prefix()
        
        # Rileva dispositivi attivi
        active_devices = get_active_ips(ip_prefix=ip_prefix, output_file=output_file)
        
        with progress_lock:
            scan_progress = {'status': 'Analyzing', 'percentage': 50, 'message': 'Analisi dei dispositivi attivi'}
        
        if active_devices:
            # Esegui l'analisi dei dispositivi
            analyze_devices(
                max_threads_analysis=30,
                output_file=summary_file,
                active_devices=active_devices,
                ports=ports,
                verbosity=verbosity
            )
            with progress_lock:
                scan_progress = {'status': 'Completed', 'percentage': 100, 'message': 'Scansione completata'}
        else:
            with progress_lock:
                scan_progress = {'status': 'Completed', 'percentage': 100, 'message': 'Nessun dispositivo trovato'}
    except Exception as e:
        with progress_lock:
            scan_progress = {'status': 'Error', 'percentage': 100, 'message': f'Errore: {e}'}
    finally:
        scan_in_progress = False

@app.route('/')
def index():
    # Definisci il percorso del file JSON
    script_dir = os.path.dirname(os.path.abspath(__file__))
    summary_path = os.path.join(script_dir, 'output', 'network_summary.json')

    # Carica i dati dal file JSON
    try:
        with open(summary_path, 'r') as f:
            devices = json.load(f)
    except FileNotFoundError:
        devices = []
    except json.JSONDecodeError:
        devices = []

    with progress_lock:
        current_progress = scan_progress.copy()

    return render_template('index.html', devices=devices, scan_in_progress=scan_in_progress, scan_progress=current_progress)

@app.route('/api/devices')
def get_devices():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    summary_path = os.path.join(script_dir, 'output', 'network_summary.json')

    try:
        with open(summary_path, 'r') as f:
            devices = json.load(f)
    except FileNotFoundError:
        devices = []
    except json.JSONDecodeError:
        devices = []

    return jsonify(devices)

@app.route('/api/progress')
def get_progress():
    with progress_lock:
        current_progress = scan_progress.copy()
    return jsonify(current_progress)

@app.route('/api/update', methods=['POST'])
def update_devices():
    global scan_in_progress
    if scan_in_progress:
        return jsonify({"status": "Scan already in progress"}), 429  # Too Many Requests
    
    # Definisci i percorsi dei file di output
    script_dir = os.path.dirname(os.path.abspath(__file__))
    active_output_path = os.path.join(script_dir, 'output', 'active_ips.txt')
    summary_output_path = os.path.join(script_dir, 'output', 'network_summary.json')
    
    # Ottieni i dati dal corpo della richiesta (se necessari)
    data = request.get_json()
    prefix = data.get('prefix') if data else None
    ports = data.get('ports') if data else '1-1024'
    verbosity = data.get('verbosity') if data else False

    # Avvia la scansione in un thread separato per non bloccare la richiesta
    thread = threading.Thread(target=perform_scan, args=(active_output_path, summary_output_path, prefix, ports, verbosity))
    thread.start()
    
    return jsonify({"status": "Scan started"}), 202  # Accepted

if __name__ == '__main__':
    app.run(debug=True)
