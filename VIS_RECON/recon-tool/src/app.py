from flask import Flask, render_template, request, jsonify
import subprocess
import logging
import pandas as pd

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

scan_process = None

def get_latest_version(service_name):
    latest_versions = {
        'http': '2.4.54',
        'ssh': '8.6',
        'ftp': '3.0.3'
    }
    return latest_versions.get(service_name, 'Unknown')

def search_exploits(service_name, os_name):
    try:
        logging.info(f"Searching exploits for {service_name} on {os_name} in metasploit_exploits.xlsx")
        exploits = []
        df = pd.read_excel(r'C:/Users/bhush/OneDrive/Documents/projectR2/files (1)/recon-tool/metasploit_exploits.xlsx')
        for index, row in df.iterrows():
            if service_name in row['service'] and os_name in row['os']:
                exploit_title = row['exploit']
                exploits.append({'title': exploit_title})
                if len(exploits) == 2:  # Limit to 2 exploits
                    break
        logging.info(f"Found exploits: {exploits}")
        return exploits
    except Exception as e:
        logging.error(f"Failed to search exploits for {service_name} on {os_name}: {str(e)}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan():
    global scan_process
    target_ip = request.args.get('target')
    logging.info(f"Starting scan for target IP: {target_ip}")
    try:
        # First scan to find open ports and services
        logging.info(f"Running nmap for {target_ip}")
        scan_process = subprocess.Popen(
            [r'C:/Program Files (x86)/Nmap/nmap.exe', '-sV', '-O', target_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = scan_process.communicate()
        logging.info(f"Nmap output: {stdout}")
        
        scan_result = []
        os_name = None
        for line in stdout.split('\n'):
            if 'open' in line:
                parts = line.split()
                service_name = parts[2]
                version = ' '.join(parts[3:])
                latest_version = get_latest_version(service_name)
                scan_result.append({
                    'port': parts[0],
                    'state': parts[1],
                    'service': service_name,
                    'version': version,
                    'latest_version': latest_version
                })
            elif 'OS details' in line:
                os_name = line.split(':')[1].strip()

        # Second scan to find CVEs
        logging.info(f"Running nmap vuln scan for {target_ip}")
        scan_process = subprocess.Popen(
            [r'C:/Program Files (x86)/Nmap/nmap.exe', '-Pn', '--script', 'vuln', target_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = scan_process.communicate()
        logging.info(f"Nmap vuln scan output: {stdout}")

        cve_list = []
        for line in stdout.split('\n'):
            if 'CVE-' in line:
                cve_id = line.split()[0]
                description = ' '.join(line.split()[1:])
                exploits = search_exploits(service_name, os_name)
                exploit_command = exploits[0]['title'] if exploits else "No known exploit available"
                cve_list.append({
                    'ID': cve_id,
                    'DESCRIPTION': description,
                    'EXPLOIT': exploit_command
                })

        return jsonify(results=scan_result, os_name=os_name, cves=cve_list)
    except subprocess.CalledProcessError as e:
        logging.error(f"Scan failed. Error: {str(e)}, Output: {e.output}")
        return jsonify(error=str(e), output=e.output)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        return jsonify(error=str(e))

@app.route('/cancel_scan', methods=['POST'])
def cancel_scan():
    global scan_process
    if scan_process:
        scan_process.terminate()
        scan_process = None
        return jsonify({"status": "Scan cancelled"})
    return jsonify({"status": "No scan to cancel"})

if __name__ == '__main__':
    app.run(debug=True, port=5001)