# PANCAKE : Ports Analysis & Network Connectivity Assessment Kit Engine

## Introduzione

Sei giunto di fronte al **PANCAKE**! Questo progetto è uno strumento completo per l'analisi della rete locale, che consente di rilevare dispositivi attivi, analizzare porte aperte, identificare i sistemi operativi e visualizzare tutte queste informazioni tramite un'interfaccia web elegante e intuitiva.

## Requisiti

Per eseguire correttamente questo progetto su **Windows 11**, assicurati di avere i seguenti prerequisiti:

1. **Python 3.8 o superiore**
   - [Scarica Python](https://www.python.org/downloads/)

2. **Nmap**
   - [Scarica Nmap per Windows](https://nmap.org/download.html)
   - Durante l'installazione, **aggiungi Nmap al PATH** per poterlo eseguire da qualsiasi terminale.

3. **Ambiente Virtuale Python (opzionale ma consigliato)**
   - Permette di isolare le dipendenze del progetto.

## Installazione

Segui questi passaggi per configurare ed eseguire il progetto:

### 1. Clonare il Repository (Se Applicabile)

Se vuoi usare questo progetto, clonalo utilizzando il comando:

git clone https://github.com/Uhrien/PANCAKE.git
cd PANCAKE

Nota: Se hai già scaricato la cartella del progetto, assicurati di navigare nella directory corretta.

### 2. Creare e Attivare un Ambiente Virtuale

Creare un ambiente virtuale aiuta a gestire le dipendenze del progetto senza conflitti con altri progetti Python.

a. **Creazione dell'Ambiente Virtuale (Opzionale)**

Apri il Prompt dei Comandi o PowerShell e naviga nella cartella del progetto:

cd percorso\alla\cartella\del\progetto

Crea l'ambiente virtuale chiamato venv:

python -m venv venv

b. **Attivazione dell'Ambiente Virtuale**

Su Windows (Prompt dei Comandi):

venv\Scripts\activate

Su Windows (PowerShell):

.\venv\Scripts\Activate.ps1

Nota: Se incontri un errore di esecuzione script in PowerShell, potresti dover modificare la politica di esecuzione:

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

3. **Installare le Dipendenze**

Con l'ambiente virtuale attivo, aggiorna pip e installa le dipendenze necessarie:

pip install --upgrade pip
pip install -r requirements.txt

## Esecuzione del Progetto
Una volta completata l'installazione, segui questi passaggi per avviare l'applicazione:

1. **Avviare l'Applicazione Flask**

Nel terminale, assicurati di essere nella directory principale del progetto e che l'ambiente virtuale sia attivo. Esegui il file app.py:

python app.py


Dovresti vedere un output simile a questo:

 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment.
Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 123-456-789


2. **Aprire l'Interfaccia Web**

Apri il tuo browser preferito e vai all'indirizzo:

http://127.0.0.1:5000/

3. **Aggiornare i Dati**
Premere il Pulsante "Aggiorna Dati":

Nella pagina web, clicca sul pulsante "Aggiorna Dati" per avviare la scansione della rete.

Una barra di progresso e un messaggio indicheranno lo stato della scansione in corso.

La scansione potrebbe richiedere alcuni minuti a seconda delle dimensioni della rete e del numero di dispositivi presenti.


## Visualizzare i Risultati:

Una volta completata la scansione, la pagina si aggiornerà automaticamente mostrando i dispositivi rilevati con le relative informazioni.

### Struttura del Progetto

Ecco una panoramica della struttura delle cartelle del progetto:

PANCAKE/
│
├── app.py                   # File principale dell'applicazione Flask
├── main.py                  # (Opzionale) File principale per la scansione
├── README.md                # Questo file
├── requirements.txt         # Elenco delle dipendenze Python
├── lib/                     # Libreria con moduli per l'analisi della rete
│   ├── device_analysis.py
│   ├── local_network_analysis.py
│   ├── utils.py
│   └── __init__.py
├── templates/               # Template HTML per Flask
│   └── index.html
├── static/                  # File statici (CSS, JS, immagini)
│   └── css/
│       └── styles.css
└── output/                  # File di output generati dall'applicazione
    ├── active_ips.txt
    └── network_summary.json

### Risoluzione dei Problemi

Ecco alcuni problemi comuni e come risolverli:

**Nmap Non Riconosciuto:**

Assicurati che Nmap sia installato e aggiunto al PATH di sistema. Puoi verificare eseguendo nmap --version nel terminale.
Permessi di Esecuzione su PowerShell:

**Se ricevi errori durante l'attivazione dell'ambiente virtuale in PowerShell, aggiorna la politica di esecuzione:**

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

**File network_summary.json Mancante o Vuoto:**

Assicurati che la scansione sia stata completata correttamente e che Nmap abbia rilevato dispositivi attivi nella tua rete.

**Porta 5000 Occupata:**

Se la porta 5000 è già in uso, puoi specificarne un'altra modificando la riga app.run(debug=True) in app.py:

app.run(debug=True, port=5001)

E poi accedi all'interfaccia web su http://127.0.0.1:5001/.