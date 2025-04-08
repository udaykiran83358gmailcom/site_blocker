from flask import Flask, request, render_template, redirect, url_for
import os
import platform
import subprocess
import socket
import json
import logging
import threading
import time

app = Flask(__name__)
BLOCKLIST_FILE = "blocked_sites.json"

# ---------- Setup Logging ----------
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s')

# ---------- Helper Functions ----------
def is_windows():
    return platform.system().lower() == "windows"

def is_linux():
    return platform.system().lower() == "linux"

def resolve_domain_to_ip(domain, retries=3):
    for attempt in range(retries):
        try:
            ip = socket.gethostbyname(domain)
            logging.debug(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            logging.warning(f"Attempt {attempt + 1} failed to resolve {domain}: {e}")
    return None

def load_blocklist():
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_blocklist(blocklist):
    with open(BLOCKLIST_FILE, 'w') as f:
        json.dump(blocklist, f, indent=4)

def run_command(command):
    logging.debug(f"Executing: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"Command failed: {result.stderr}")
        return False
    logging.info(f"Command succeeded: {result.stdout}")
    return True

# ---------- Firewall Commands ----------
def block_with_netsh(domain, ip):
    rule_name = f"Block_{domain}"
    return run_command(f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}')

def unblock_netsh(domain):
    rule_name = f"Block_{domain}"
    return run_command(f'netsh advfirewall firewall delete rule name="{rule_name}"')

def block_with_iptables(domain, ip):
    return run_command(f"sudo iptables -A OUTPUT -d {ip} -j DROP")

def unblock_iptables(domain, ip):
    return run_command(f"sudo iptables -D OUTPUT -d {ip} -j DROP")

# ---------- Flask Routes ----------
@app.route('/', methods=['GET', 'POST'])
def home():
    message = ""
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        ip = request.form.get('ip', '').strip()
        duration = int(request.form.get("duration", 0))  # in minutes

        if not domain:
            message = "❌ Please enter a domain"
            return render_template('index.html', blocked=load_blocklist(), message=message)

        if not ip:
            ip = resolve_domain_to_ip(domain)
            if not ip:
                message = f"❌ Could not resolve IP for {domain}"
                return render_template('index.html', blocked=load_blocklist(), message=message)

        success = False
        if is_windows():
            success = block_with_netsh(domain, ip)
        elif is_linux():
            success = block_with_iptables(domain, ip)
        else:
            message = "❌ Unsupported OS"
            return render_template('index.html', blocked=load_blocklist(), message=message)

        if success:
            blocklist = load_blocklist()
            blocklist[domain] = ip
            save_blocklist(blocklist)
            message = f"✅ Blocked {domain} ({ip})"

            if duration > 0:
                def unblock_after_delay(domain, ip, minutes):
                    logging.info(f"⏳ Will unblock {domain} in {minutes} minute(s)...")
                    time.sleep(minutes * 60)
                    if is_windows():
                        unblock_netsh(domain)
                    elif is_linux():
                        unblock_iptables(domain, ip)
                    blocklist = load_blocklist()
                    blocklist.pop(domain, None)
                    save_blocklist(blocklist)
                    logging.info(f"✅ Automatically unblocked {domain} after {minutes} minute(s)")

                threading.Thread(target=unblock_after_delay, args=(domain, ip, duration), daemon=True).start()
        else:
            message = f"❌ Failed to block {domain} ({ip})"

    return render_template('index.html', blocked=load_blocklist(), message=message)

@app.route('/unblock/<path:domain>')
def unblock(domain):
    blocklist = load_blocklist()
    ip = blocklist.get(domain)
    if not ip:
        return redirect(url_for('home'))

    success = False
    if is_windows():
        success = unblock_netsh(domain)
    elif is_linux():
        success = unblock_iptables(domain, ip)

    if success:
        blocklist.pop(domain)
        save_blocklist(blocklist)

    return redirect(url_for('home'))

# ---------- Run App ----------
from flask import Flask, render_template
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # use PORT Render provides
    app.run(host='0.0.0.0', port=port)


