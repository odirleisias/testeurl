import requests
import socket
import ssl
import threading
import time
import csv
import os
import tldextract
from flask import Flask, render_template, request, redirect, url_for
from urllib.parse import urlparse
from datetime import datetime

# Tratamento condicional para dnspython
try:
    import dns.resolver
    DNS_ENABLED = True
except ImportError:
    DNS_ENABLED = False
    print("Aviso: Módulo dnspython não instalado. Funcionalidades de DNS desativadas.")

app = Flask(__name__)

results_cache = {"timestamp": "", "results": [], "stats": {}}
results_lock = threading.Lock()
downtime_timer = {}
proxy_state_history = {}  # Para rastrear o estado do proxy

# Arquivos de configuração
CSV_NS_LOG = 'log_ns_changes.csv'
CSV_DOWNTIME_LOG = 'log_downtime.csv'
CSV_PROXY_LOG = 'log_proxy_changes.csv'
CIS_NAMESERVERS_FILE = 'cis_nameservers.txt'
URLS_FILE = 'urls.txt'

def load_cis_nameservers():
    if not os.path.exists(CIS_NAMESERVERS_FILE):
        # Cria arquivo padrão se não existir
        with open(CIS_NAMESERVERS_FILE, 'w') as f:
            f.write("ns102.name.cloud.ibm.com\nns173.name.cloud.ibm.com")
    
    with open(CIS_NAMESERVERS_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def save_cis_nameservers(nameservers):
    with open(CIS_NAMESERVERS_FILE, 'w') as f:
        f.write("\n".join(nameservers))

def load_urls():
    if not os.path.exists(URLS_FILE):
        open(URLS_FILE, 'w').close()  # Cria arquivo vazio
    
    with open(URLS_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def save_urls(urls):
    with open(URLS_FILE, 'w') as f:
        f.write("\n".join(urls))

def log_csv(filename, row, header=None):
    file_exists = os.path.isfile(filename)
    with open(filename, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header or row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def clear_logs():
    logs = [CSV_NS_LOG, CSV_DOWNTIME_LOG, CSV_PROXY_LOG]
    for log in logs:
        if os.path.exists(log):
            os.remove(log)

def extract_domain(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url
        parsed = urlparse(url)
    return parsed.netloc.split(':')[0], parsed.scheme

def get_base_domain(domain):
    extracted = tldextract.extract(domain)
    return f"{extracted.domain}.{extracted.suffix}"

def get_public_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"ERRO: {str(e)}"

def is_cis_proxy(ip):
    """Verifica se o IP pertence ao proxy do CIS (172.66.x.x ou 172.67.x.x)"""
    return ip.startswith('172.66.') or ip.startswith('172.67.')

def get_nameservers(domain):
    if not DNS_ENABLED:
        return ["DNS desativado"]

    base_domain = get_base_domain(domain)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8']

    try:
        answers = resolver.resolve(base_domain, 'NS')
        return sorted([ns.to_text().rstrip('.') for ns in answers])
    except dns.resolver.NoAnswer:
        return ["Sem registros NS"]
    except dns.resolver.NXDOMAIN:
        return ["Domínio não existe"]
    except dns.resolver.Timeout:
        return ["Timeout na consulta"]
    except Exception as e:
        return [f"ERRO: {str(e)}"]

def check_ssl(domain):
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert() is not None
    except Exception:
        return False

def check_website(url):
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': '*/*',
        'Connection': 'keep-alive'
    }

    try:
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=5, verify=False)
        return response.status_code in [200, 301, 302, 401, 403]
    except Exception:
        return False

def is_cis_migrated(nameservers):
    if not DNS_ENABLED:
        return False
    
    cis_nameservers = load_cis_nameservers()
    return any(ns in cis_nameservers for ns in nameservers)

def check_url(url):
    try:
        domain, scheme = extract_domain(url)
        full_url = f"{scheme}://{domain}" if "://" not in url else url

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        current_ip = get_public_ip(domain)
        nameservers = get_nameservers(domain)
        cis_migrated = is_cis_migrated(nameservers)
        proxy_active = is_cis_proxy(current_ip) if not current_ip.startswith('ERRO:') else False

        # Rastreamento de estado do proxy
        proxy_changed = False
        proxy_activated = False
        
        if domain in proxy_state_history:
            previous_state = proxy_state_history[domain]
            if previous_state != proxy_active:
                proxy_changed = True
                proxy_activated = proxy_active
                log_csv(CSV_PROXY_LOG, {
                    "timestamp": now_str,
                    "domain": domain,
                    "previous_state": "Ativado" if previous_state else "Desativado",
                    "new_state": "Ativado" if proxy_active else "Desativado"
                }, header=["timestamp", "domain", "previous_state", "new_state"])
        else:
            # Primeira verificação - registrar estado inicial
            log_csv(CSV_PROXY_LOG, {
                "timestamp": now_str,
                "domain": domain,
                "previous_state": "N/A",
                "new_state": "Ativado" if proxy_active else "Desativado"
            }, header=["timestamp", "domain", "previous_state", "new_state"])
        
        proxy_state_history[domain] = proxy_active

        # NS tracking
        ns_changed = False
        if domain in ns_history and ns_history[domain] != nameservers:
            ns_changed = True
            log_csv(CSV_NS_LOG, {
                "timestamp": now_str,
                "domain": domain,
                "old_ns": ", ".join(ns_history[domain]),
                "new_ns": ", ".join(nameservers)
            }, header=["timestamp", "domain", "old_ns", "new_ns"])
        ns_history[domain] = nameservers

        # SSL
        ssl_present = check_ssl(domain) if scheme == 'https' else False

        # Disponibilidade
        accessible = check_website(full_url)

        # Queda (downtime)
        if not accessible:
            if domain not in downtime_timer:
                downtime_timer[domain] = time.time()
        else:
            if domain in downtime_timer:
                start_time = downtime_timer[domain]
                end_time = time.time()
                duration = round(end_time - start_time, 2)
                log_csv(CSV_DOWNTIME_LOG, {
                    "domain": domain,
                    "start": datetime.fromtimestamp(start_time).strftime("%d/%m/%Y %H:%M:%S"),
                    "end": datetime.fromtimestamp(end_time).strftime("%d/%m/%Y %H:%M:%S"),
                    "duration_seconds": duration
                }, header=["domain", "start", "end", "duration_seconds"])
                del downtime_timer[domain]

        return {
            "url": full_url,
            "domain": domain,
            "ip": current_ip,
            "accessible": accessible,
            "ssl_present": ssl_present,
            "ns_changed": ns_changed,
            "nameservers": ", ".join(nameservers),
            "cis_migrated": cis_migrated,
            "proxy_active": proxy_active,
            "proxy_changed": proxy_changed,
            "proxy_activated": proxy_activated if proxy_changed else None,
            "status": "OK" if accessible else "FORA"
        }
    except Exception as e:
        return {
            "url": url,
            "error": f"Erro na verificação: {str(e)}",
            "status": "ERRO"
        }

def calculate_stats(results):
    total = len(results)
    ok_count = error_count = migrated_count = 0

    for item in results:
        if 'error' in item:
            error_count += 1
        elif item['accessible']:
            ok_count += 1
        if item.get('cis_migrated', False):
            migrated_count += 1

    not_ok_count = total - ok_count - error_count
    percentage_ok = round((ok_count / total) * 100, 2) if total > 0 else 0
    percentage_migrated = round((migrated_count / total) * 100, 2) if total > 0 else 0

    return {
        "total": total,
        "ok": ok_count,
        "not_ok": not_ok_count,
        "errors": error_count,
        "migrated": migrated_count,
        "percentage_ok": percentage_ok,
        "percentage_migrated": percentage_migrated
    }

def update_cache():
    while True:
        try:
            urls = load_urls()
            new_results = [check_url(url) for url in urls]
            stats = calculate_stats(new_results)

            with results_lock:
                results_cache['results'] = new_results
                results_cache['stats'] = stats
                results_cache['timestamp'] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        except Exception as e:
            print(f"Erro na atualização: {e}")

        time.sleep(25)  # Atualizado para 25 segundos

@app.route('/')
def dashboard():
    with results_lock:
        cis_nameservers = load_cis_nameservers()
        return render_template(
            'dashboard.html',
            results=results_cache['results'],
            stats=results_cache['stats'],
            timestamp=results_cache['timestamp'],
            cis_nameservers=", ".join(cis_nameservers),
            dns_enabled=DNS_ENABLED
        )

@app.route('/historico')
def historico():
    def read_csv(filename):
        if not os.path.isfile(filename):
            return []
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            return list(reader)

    ns_changes = read_csv(CSV_NS_LOG)
    downtimes = read_csv(CSV_DOWNTIME_LOG)
    proxy_changes = read_csv(CSV_PROXY_LOG)

    return render_template(
        'historico.html',
        ns_changes=ns_changes,
        downtimes=downtimes,
        proxy_changes=proxy_changes
    )

@app.route('/clear-logs', methods=['POST'])
def clear_logs_route():
    clear_logs()
    return redirect(url_for('historico'))

@app.route('/config', methods=['GET', 'POST'])
def config():
    if request.method == 'POST':
        # Processar form de nameservers
        if 'nameserver' in request.form:
            ns = request.form['nameserver'].strip()
            if ns:
                nameservers = load_cis_nameservers()
                if ns not in nameservers:
                    nameservers.append(ns)
                    save_cis_nameservers(nameservers)
        
        # Processar remoção de nameserver
        elif 'remove_ns' in request.form:
            ns_to_remove = request.form['remove_ns']
            nameservers = load_cis_nameservers()
            nameservers = [ns for ns in nameservers if ns != ns_to_remove]
            save_cis_nameservers(nameservers)
        
        return redirect(url_for('config'))
    
    nameservers = load_cis_nameservers()
    return render_template('config.html', nameservers=nameservers)

@app.route('/urls', methods=['GET', 'POST'])
def manage_urls():
    if request.method == 'POST':
        # Adicionar URL
        if 'new_url' in request.form:
            url = request.form['new_url'].strip()
            if url:
                urls = load_urls()
                if url not in urls:
                    urls.append(url)
                    save_urls(urls)
        
        # Remover URL
        elif 'remove_url' in request.form:
            url_to_remove = request.form['remove_url']
            urls = load_urls()
            urls = [u for u in urls if u != url_to_remove]
            save_urls(urls)
        
        return redirect(url_for('manage_urls'))
    
    urls = load_urls()
    return render_template('urls.html', urls=urls)

if __name__ == '__main__':
    # Inicialização de variáveis
    ns_history = {}
    
    # Criar arquivos se não existirem
    if not os.path.exists(CIS_NAMESERVERS_FILE):
        save_cis_nameservers(["ns102.name.cloud.ibm.com", "ns173.name.cloud.ibm.com"])
    
    if not os.path.exists(URLS_FILE):
        save_urls([])
    
    threading.Thread(target=update_cache, daemon=True).start()
    app.run(host='0.0.0.0', port=80, threaded=True)
