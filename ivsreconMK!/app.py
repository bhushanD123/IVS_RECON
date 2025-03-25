from flask import Flask, render_template, request, jsonify, send_file
import nmap
import json
import xmltodict
from datetime import datetime
import sqlite3
import os
import requests
import re
import urllib.parse
import html
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import warnings
import dns.resolver
import socket
import subprocess
import threading
import queue
import concurrent.futures
from werkzeug.utils import secure_filename
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
warnings.filterwarnings('ignore')

# Define Nmap path explicitly
NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'reports'
app.config['DATABASE'] = 'scans.db'

# Ensure the reports directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                date TEXT NOT NULL,
                status TEXT NOT NULL,
                open_ports INTEGER DEFAULT 0,
                vulnerabilities INTEGER DEFAULT 0,
                report_path TEXT
            )
        ''')
        conn.commit()

# Get database connection
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database on startup
init_db()

def get_cves_for_service(service_name, version):
    """Fetch CVEs for a specific service and version from NVD"""
    try:
        # Clean up version string to remove any unwanted characters
        if version:
            version = re.sub(r'[^0-9.]', '', version)
        
        if not service_name:
            return []
            
        # Construct search query
        search_term = service_name
        if version:
            search_term += f" {version}"
            
        # Query NVD API
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": search_term,
            "resultsPerPage": 10  # Limit to top 10 CVEs
        }
        
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_item = vuln.get('cve', {})
                cve_id = cve_item.get('id')
                description = next((desc.get('value') for desc in cve_item.get('descriptions', []) 
                                 if desc.get('lang') == 'en'), '')
                severity = "Unknown"
                
                # Get CVSS score if available
                metrics = cve_item.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    severity = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'Unknown')
                elif 'cvssMetricV2' in metrics:
                    severity = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 'Unknown')
                
                cves.append({
                    'id': cve_id,
                    'description': description,
                    'severity': severity
                })
            
            return cves
    except Exception as e:
        print(f"Error fetching CVEs: {str(e)}")
        return []

def detect_api_endpoints(target_ip, port, service):
    """Detect potential API endpoints and web services"""
    endpoints = []
    
    try:
        # Common API paths to check
        api_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/graphql',
            '/swagger',
            '/swagger-ui.html',
            '/openapi',
            '/docs',
            '/redoc',
            '/wp-json',  # WordPress REST API
            '/api-docs'
        ]
        
        # Only check HTTP/HTTPS services
        if service.lower() in ['http', 'https']:
            protocol = 'https' if service.lower() == 'https' else 'http'
            base_url = f"{protocol}://{target_ip}:{port}"
            
            # Try to detect API documentation endpoints
            for path in api_paths:
                try:
                    url = f"{base_url}{path}"
                    response = requests.get(url, timeout=2, verify=False)
                    
                    if response.status_code != 404:
                        content_type = response.headers.get('Content-Type', '').lower()
                        
                        # Detect API type
                        api_type = 'Unknown'
                        if 'swagger' in url or 'openapi' in url:
                            api_type = 'OpenAPI/Swagger'
                        elif 'graphql' in url:
                            api_type = 'GraphQL'
                        elif 'wp-json' in url:
                            api_type = 'WordPress REST API'
                        elif 'json' in content_type:
                            api_type = 'REST API'
                        
                        endpoints.append({
                            'url': url,
                            'type': api_type,
                            'status_code': response.status_code,
                            'content_type': content_type
                        })
                except:
                    continue
                    
            # Try to detect common web applications
            try:
                response = requests.get(base_url, timeout=2, verify=False)
                server = response.headers.get('Server', '')
                powered_by = response.headers.get('X-Powered-By', '')
                
                if server or powered_by:
                    endpoints.append({
                        'url': base_url,
                        'type': 'Web Server',
                        'server': server,
                        'powered_by': powered_by
                    })
            except:
                pass
                
    except Exception as e:
        print(f"Error detecting API endpoints: {str(e)}")
    
    return endpoints

def parse_nmap_xml(xml_file):
    try:
        with open(xml_file) as fd:
            doc = xmltodict.parse(fd.read())
            return doc
    except:
        return None

def check_xss_vulnerability(url, params=None):
    """Test for XSS vulnerabilities in the given URL"""
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '\'><img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '" onmouseover="alert(1)',
        '\' onmouseover=\'alert(1)',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><svg/onload=alert(1)>',
        '\'"--><script>alert(1)</script>',
        '<body onload=alert(1)>',
        '<ScRiPt>alert(1)</ScRiPt>'
    ]
    
    results = []
    try:
        # First, get the original page and find forms
        session = requests.Session()
        response = session.get(url, verify=False, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Test URL parameters if they exist
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in query_params:
                for payload in xss_payloads:
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed_url.fragment
                    ))
                    
                    try:
                        response = session.get(test_url, verify=False, timeout=3)
                        if payload in response.text and not html.escape(payload) in response.text:
                            results.append({
                                'type': 'Reflected XSS',
                                'location': 'URL Parameter',
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url
                            })
                    except:
                        continue
        
        # Test each form
        for form in forms:
            form_url = urljoin(url, form.get('action', ''))
            method = form.get('method', 'get').lower()
            
            # Get all input fields
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                field_name = input_field.get('name')
                if not field_name:
                    continue
                
                for payload in xss_payloads:
                    form_data = {field_name: payload}
                    
                    try:
                        if method == 'post':
                            response = session.post(form_url, data=form_data, verify=False, timeout=3)
                        else:
                            response = session.get(form_url, params=form_data, verify=False, timeout=3)
                            
                        if payload in response.text and not html.escape(payload) in response.text:
                            results.append({
                                'type': 'Reflected XSS',
                                'location': 'Form Field',
                                'parameter': field_name,
                                'payload': payload,
                                'url': form_url,
                                'method': method
                            })
                    except:
                        continue
                        
        # Check for DOM-based XSS
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string
            if script_content:
                dangerous_patterns = [
                    'document.write',
                    'document.writeln',
                    'innerHTML',
                    'outerHTML',
                    'eval(',
                    'setTimeout(',
                    'setInterval(',
                    'location.hash',
                    'location.search'
                ]
                
                for pattern in dangerous_patterns:
                    if pattern in script_content:
                        results.append({
                            'type': 'Potential DOM-based XSS',
                            'location': 'JavaScript',
                            'evidence': pattern,
                            'url': url
                        })
                        
    except Exception as e:
        print(f"Error checking XSS: {str(e)}")
    
    return results

def perform_dns_enumeration(target):
    """Perform DNS enumeration using various record types"""
    dns_results = {
        'records': [],
        'subdomains': [],
        'services': []
    }
    
    # Common DNS record types to query
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
    
    try:
        # Check if target is IP or domain
        try:
            socket.inet_aton(target)
            # If we get here, target is an IP
            try:
                hostname = socket.gethostbyaddr(target)[0]
                dns_results['records'].append({
                    'type': 'PTR',
                    'name': target,
                    'value': hostname
                })
                # Use the resolved hostname for further enumeration
                target = hostname
            except:
                return dns_results
        except socket.error:
            # Target is already a hostname
            pass
        
        resolver = dns.resolver.Resolver()
        
        # Query each record type
        for record_type in record_types:
            try:
                answers = resolver.resolve(target, record_type)
                for answer in answers:
                    record_data = {
                        'type': record_type,
                        'name': target,
                        'value': str(answer)
                    }
                    
                    # Special handling for SRV records to identify services
                    if record_type == 'SRV':
                        service_info = {
                            'service': answer.target.to_text().rstrip('.'),
                            'port': answer.port,
                            'priority': answer.priority,
                            'weight': answer.weight
                        }
                        dns_results['services'].append(service_info)
                    
                    dns_results['records'].append(record_data)
            except Exception as e:
                continue
        
        # Subdomain enumeration using common prefixes
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server',
            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
            'staging', 'app', 'admin', 'portal', 'test', 'docs',
            'confluence', 'wiki', 'support', 'mobile', 'm'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            def check_subdomain(subdomain):
                try:
                    full_domain = f"{subdomain}.{target}"
                    answers = resolver.resolve(full_domain, 'A')
                    return {
                        'subdomain': full_domain,
                        'ip': [str(answer) for answer in answers],
                        'status': 'active'
                    }
                except:
                    return None
            
            futures = [executor.submit(check_subdomain, subdomain) 
                      for subdomain in common_subdomains]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    dns_results['subdomains'].append(result)
        
    except Exception as e:
        print(f"Error in DNS enumeration: {str(e)}")
    
    return dns_results

def perform_scan(target_ip):
    """Perform a comprehensive security scan of the target"""
    try:
        # Initialize nmap scanner with explicit path
        nm = nmap.PortScanner(nmap_search_path=[NMAP_PATH])
        
        # Perform basic port scan with OS detection
        nm.scan(target_ip, arguments='-sV -sS -Pn -O')
        
        # Parse vulnerability scan results if file exists
        vuln_results = None
        if os.path.exists('nmap_vuln_scan.xml'):
            vuln_results = parse_nmap_xml('nmap_vuln_scan.xml')
        
        scan_data = {
            'ports': [],
            'vulns': [],
            'cves': [],
            'suggested_exploits': [],
            'os_info': [],
            'api_endpoints': [],
            'xss_vulns': [],
            'dns_enum': perform_dns_enumeration(target_ip)
        }
        
        # Process port scan results and fetch CVEs
        for host in nm.all_hosts():
            # Get OS information
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    scan_data['os_info'].append({
                        'name': osmatch['name'],
                        'accuracy': osmatch['accuracy'],
                        'line': osmatch.get('line', ''),
                        'osclass': osmatch.get('osclass', [])
                    })
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service_info = nm[host][proto][port]
                    service_name = service_info.get('name', '')
                    version = service_info.get('version', '')
                    
                    scan_data['ports'].append({
                        'port': port,
                        'service': service_name,
                        'version': version,
                        'state': service_info.get('state', '')
                    })
                    
                    # Check for XSS vulnerabilities in web services
                    if service_info.get('state') == 'open' and service_name.lower() in ['http', 'https']:
                        protocol = 'https' if service_name.lower() == 'https' else 'http'
                        url = f"{protocol}://{target_ip}:{port}"
                        xss_results = check_xss_vulnerability(url)
                        if xss_results:
                            scan_data['xss_vulns'].extend(xss_results)
                    
                    # Detect API endpoints for web services
                    if service_info.get('state') == 'open':
                        endpoints = detect_api_endpoints(target_ip, port, service_name)
                        if endpoints:
                            scan_data['api_endpoints'].extend(endpoints)
                    
                    # Get CVEs for this service
                    if service_name:
                        cves = get_cves_for_service(service_name, version)
                        if cves:
                            scan_data['cves'].append({
                                'service': service_name,
                                'version': version,
                                'port': port,
                                'vulnerabilities': cves
                            })
        
        # Process vulnerability results if available
        if vuln_results and 'nmaprun' in vuln_results:
            try:
                hosts = vuln_results['nmaprun'].get('host', [])
                if not isinstance(hosts, list):
                    hosts = [hosts]
                
                for host in hosts:
                    if 'ports' in host:
                        ports = host['ports'].get('port', [])
                        if not isinstance(ports, list):
                            ports = [ports]
                        
                        for port in ports:
                            if 'script' in port:
                                scripts = port['script']
                                if not isinstance(scripts, list):
                                    scripts = [scripts]
                                
                                for script in scripts:
                                    if '@id' in script and 'table' in script:
                                        vuln_info = {
                                            'type': script['@id'],
                                            'details': script['table']
                                        }
                                        scan_data['vulns'].append(vuln_info)
            except Exception as e:
                print(f"Error processing vulnerability results: {str(e)}")
        
        # Add suggested Metasploit exploits based on detected services
        msf_exploits = {
            'http': ['exploit/multi/http/apache_mod_cgi_bash_env_exec',
                    'exploit/unix/webapp/wp_admin_shell_upload'],
            'ssh': ['exploit/multi/ssh/sshexec'],
            'ftp': ['exploit/unix/ftp/vsftpd_234_backdoor'],
            'smb': ['exploit/windows/smb/ms17_010_eternalblue']
        }
        
        for port_info in scan_data['ports']:
            service = port_info['service'].lower()
            if service in msf_exploits:
                scan_data['suggested_exploits'].extend(msf_exploits[service])
        
        return scan_data
        
    except Exception as e:
        raise Exception(f'Scan failed: {str(e)}')

def generate_pdf_report(scan_data, target_ip):
    """Generate a structured PDF report from scan data"""
    # Create the PDF file
    report_filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    
    # Container for the 'Flowable' objects
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph(f"Security Assessment Report for {target_ip}", title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    summary_text = f"""
    This report presents the findings of a comprehensive security assessment conducted on {target_ip}.
    The assessment included port scanning, service enumeration, vulnerability assessment, and DNS enumeration.
    """
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Operating System Information
    if scan_data.get('os_info'):
        elements.append(Paragraph("Operating System Information", styles['Heading2']))
        os_data = []
        for os_info in scan_data['os_info']:
            os_data.append([
                Paragraph(f"Name: {os_info['name']}", styles['Normal']),
                Paragraph(f"Accuracy: {os_info['accuracy']}%", styles['Normal'])
            ])
        os_table = Table(os_data, colWidths=[4*inch, 2*inch])
        os_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.darkgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        elements.append(os_table)
        elements.append(Spacer(1, 20))
    
    # Open Ports and Services
    if scan_data.get('ports'):
        elements.append(Paragraph("Open Ports and Services", styles['Heading2']))
        port_data = [['Port', 'Service', 'Version', 'State']]
        for port in scan_data['ports']:
            port_data.append([
                str(port['port']),
                port['service'],
                port['version'],
                port['state']
            ])
        port_table = Table(port_data, colWidths=[1*inch, 2*inch, 2*inch, 1*inch])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.darkgrey),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(port_table)
        elements.append(Spacer(1, 20))
    
    # Vulnerabilities
    if scan_data.get('vulns') or scan_data.get('cves'):
        elements.append(Paragraph("Vulnerabilities", styles['Heading2']))
        
        # CVEs
        if scan_data.get('cves'):
            elements.append(Paragraph("Common Vulnerabilities and Exposures (CVEs)", styles['Heading3']))
            cve_data = [['Service', 'CVE ID', 'Severity', 'Description']]
            for cve in scan_data['cves']:
                for vuln in cve['vulnerabilities']:
                    cve_data.append([
                        cve['service'],
                        vuln['id'],
                        vuln['severity'],
                        vuln['description']
                    ])
            cve_table = Table(cve_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 2.5*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.darkgrey),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(cve_table)
            elements.append(Spacer(1, 20))
    
    # DNS Enumeration Results
    if scan_data.get('dns_enum'):
        elements.append(Paragraph("DNS Enumeration Results", styles['Heading2']))
        
        # DNS Records
        if scan_data['dns_enum'].get('records'):
            elements.append(Paragraph("DNS Records", styles['Heading3']))
            dns_data = [['Type', 'Name', 'Value']]
            for record in scan_data['dns_enum']['records']:
                dns_data.append([
                    record['type'],
                    record['name'],
                    record['value']
                ])
            dns_table = Table(dns_data, colWidths=[1*inch, 2*inch, 3*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.darkgrey),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(dns_table)
            elements.append(Spacer(1, 20))
    
    # Build the PDF
    doc.build(elements)
    return report_path

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    db = get_db()
    scans = db.execute('SELECT * FROM scans ORDER BY date DESC').fetchall()
    db.close()
    return render_template('dashboard.html', scans=scans)

@app.route('/view_scan/<int:scan_id>')
def view_scan(scan_id):
    db = get_db()
    scan = db.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    db.close()
    
    if scan and scan['report_path'] and os.path.exists(scan['report_path']):
        with open(scan['report_path'], 'r') as f:
            scan_data = json.load(f)
        return render_template('index.html', scan_data=scan_data)
    return "Scan not found", 404

@app.route('/download_report/<int:scan_id>')
def download_report(scan_id):
    db = get_db()
    scan = db.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    db.close()
    
    if scan and scan['report_path'] and os.path.exists(scan['report_path']):
        with open(scan['report_path'], 'r') as f:
            scan_data = json.load(f)
        
        # Generate PDF report
        pdf_path = generate_pdf_report(scan_data, scan['target'])
        return send_file(pdf_path, as_attachment=True, download_name=f"security_report_{scan['target']}.pdf")
    return "Report not found", 404

@app.route('/scan', methods=['POST'])
def scan():
    target_ip = request.form.get('target_ip')
    if not target_ip:
        return jsonify({'error': 'No target IP provided'}), 400

    try:
        # Create a new scan record
        db = get_db()
        scan_id = db.execute(
            'INSERT INTO scans (target, date, status) VALUES (?, ?, ?)',
            (target_ip, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'running')
        ).lastrowid
        db.commit()
        db.close()

        # Perform the scan
        scan_data = perform_scan(target_ip)
        
        # Generate report filename
        report_filename = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
        
        # Save scan results
        with open(report_path, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        # Update scan record
        db = get_db()
        db.execute(
            '''UPDATE scans 
               SET status = ?, open_ports = ?, vulnerabilities = ?, report_path = ?
               WHERE id = ?''',
            ('completed', 
             len(scan_data.get('ports', [])),
             len(scan_data.get('vulnerabilities', [])),
             report_path,
             scan_id)
        )
        db.commit()
        db.close()

        return jsonify(scan_data)
    except Exception as e:
        # Update scan record with error
        db = get_db()
        db.execute(
            'UPDATE scans SET status = ? WHERE id = ?',
            ('failed', scan_id)
        )
        db.commit()
        db.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8080) 