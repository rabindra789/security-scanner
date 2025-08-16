import nmap
import json
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from colorama import init, Fore, Style  # For colored console logs (optional)
from fpdf import FPDF

init()  # Initialize colorama

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
os.makedirs('reports', exist_ok=True)

# Database model for scan history
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    target = db.Column(db.String(255))
    ports = db.Column(db.String(255))
    verbose = db.Column(db.Boolean)
    os_detection = db.Column(db.Boolean)
    service_detection = db.Column(db.Boolean)
    vuln_scan = db.Column(db.Boolean)
    results = db.Column(db.Text)  # Store results as JSON string

# Create database tables
with app.app_context():
    db.create_all()

def scan_target(target, ports='1-1024', verbose=False, os_detection=False, service_detection=False, vuln_scan=False):
    """Performs a security scan using Nmap."""
    scanner = nmap.PortScanner()
    args = f'-p {ports}'
    if verbose:
        args += ' -v'
    if os_detection:
        args += ' -O'
    if service_detection:
        args += ' -sV'
    if vuln_scan:
        args += ' --script vuln'
    
    print(f"{Fore.GREEN}Starting scan on {target} with args: {args}{Style.RESET_ALL}")
    try:
        scanner.scan(target, arguments=args)
    except nmap.PortScannerError as e:
        return {'error': str(e)}
    
    results = {}
    for host in scanner.all_hosts():
        results[host] = {
            'status': scanner[host].state(),
            'hostname': scanner[host].hostname(),
            'protocols': {}
        }
        if os_detection and 'osclass' in scanner[host]:
            results[host]['os'] = scanner[host]['osclass']
        
        for proto in scanner[host].all_protocols():
            results[host]['protocols'][proto] = {}
            ports = scanner[host][proto].keys()
            for port in ports:
                port_info = scanner[host][proto][port]
                results[host]['protocols'][proto][port] = {
                    'state': port_info['state'],
                    'name': port_info['name'],
                    'product': port_info.get('product', 'unknown'),
                    'version': port_info.get('version', 'unknown')
                }
                if vuln_scan and 'script' in port_info:
                    results[host]['protocols'][proto][port]['vulnerabilities'] = port_info['script']
    
    return results

def generate_pdf_report(scan):
    """
    Generate a PDF report for a given Scan object.
    """
    results = json.loads(scan.results)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)

    pdf.cell(0, 10, "Web security Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Traget: {scan.target}", ln=True)
    pdf.cell(0, 10, f"Timestammp: {scan.timestamp}", ln=True)
    pdf.cell(0, 10, f"Ports: {scan.ports}", ln=True)
    pdf.cell(0, 10, f"Options - Verbose: {scan.verbose}, OS: {scan.os_detection}, Service:  {scan.service_detection}, Vulnerability Scan: {scan.vuln_scan}", ln=True)
    pdf.ln(5)

    for host, host_info in results.items():
        pdf.set_font("Arial", "B",12)
        pdf.cell(0, 10, f"Host: {host} ({host_info.get('hostname', '')})", ln=True)
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 8, f"status: {host_info.get('status', 'unknown')}", ln=True)
        if 'os' in host_info:
            pdf.cell(0, 8, f"OS Info: {host_info['os']}", ln=True)
        
        for proto, ports in host_info.get('protocols', {}).items():
            pdf.cell(0, 8, f"Protocol: {proto}", ln=True)
            for port, info in ports.items():
                line = f"Port {port} - {info.get('name', '')} ({info.get('product', '')}/{info.get('version', '')}) State: {info.get('state')}"
                if 'vulnerabilities' in info:
                    line += f" | Vulnerabilities: {info['vulnerabilities']}"
                pdf.multi_cell(0, 8, line)
        pdf.ln(3)

    filename = f"scan_report_{scan.id}.pdf"
    pdf.output(f"reports/{filename}")
    return filename

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form['target']
        ports = request.form.get('ports', '1-1024')
        verbose = 'verbose' in request.form
        os_detection = 'os_detection' in request.form
        service_detection = 'service_detection' in request.form
        vuln_scan = 'vuln_scan' in request.form
        
        results = scan_target(target, ports, verbose, os_detection, service_detection, vuln_scan)
        
        # Store in database
        new_scan = Scan(
            target=target,
            ports=ports,
            verbose=verbose,
            os_detection=os_detection,
            service_detection=service_detection,
            vuln_scan=vuln_scan,
            results=json.dumps(results)
        )
        db.session.add(new_scan)
        db.session.commit()
        
        return render_template('results.html', results=results)
    
    return render_template('index.html')

@app.route('/history')
def history():
    scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1818, debug=True)

@app.route('/download/<int:scan_id>')
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    os.makedirs('reports', exist_ok=True)
    filename = generate_pdf_report(scan)
    return send_from_directory('reports', filename, as_attachment=True)