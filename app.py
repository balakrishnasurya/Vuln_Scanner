from flask import Flask, render_template, jsonify, request, send_file, url_for
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend
import matplotlib.pyplot as plt
import numpy as np
import io
import base64
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import os
import time
from datetime import datetime
import pdfkit
import sys

app = Flask(__name__)

# Configure wkhtmltopdf path
if sys.platform == "win32":
    WKHTMLTOPDF_PATH = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
else:
    WKHTMLTOPDF_PATH = 'wkhtmltopdf'  # Linux/Mac usually have it in PATH

# Initialize PDF configuration
try:
    config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
    print(f"wkhtmltopdf configured at: {WKHTMLTOPDF_PATH}")
except Exception as e:
    print(f"Error configuring wkhtmltopdf: {e}")
    config = None

# Ensure directories exist with absolute paths
base_dir = os.path.abspath(os.path.dirname(__file__))
static_dir = os.path.join(base_dir, 'static')
reports_dir = os.path.join(static_dir, 'reports')
images_dir = os.path.join(static_dir, 'images')

for dir_path in [reports_dir, images_dir]:
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

# Security vulnerability check functions
def check_for_header_vulnerabilities(headers):
    vulnerabilities = []
    
    # Check for missing security headers
    security_headers = {
        'Strict-Transport-Security': 'Missing HSTS header - vulnerable to protocol downgrade attacks.',
        'Content-Security-Policy': 'Missing CSP header - vulnerable to XSS attacks.',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options header - vulnerable to MIME-sniffing attacks.',
        'X-Frame-Options': 'Missing X-Frame-Options header - vulnerable to clickjacking attacks.',
        'X-XSS-Protection': 'Missing X-XSS-Protection header - reduced protection against XSS attacks.'
    }
    
    for header, message in security_headers.items():
        if header not in headers:
            vulnerabilities.append({
                'type': 'Missing Security Header',
                'name': header,
                'description': message,
                'severity': 'Medium'
            })
    
    return vulnerabilities

def check_for_form_vulnerabilities(soup, url):
    vulnerabilities = []
    
    forms = soup.find_all('form')
    for i, form in enumerate(forms):
        # Check if the form uses HTTPS
        if form.get('action') and form.get('action').startswith('http:'):
            vulnerabilities.append({
                'type': 'Insecure Form',
                'name': f'Form {i+1} submits over HTTP',
                'description': 'Form submits data over unencrypted HTTP connection.',
                'severity': 'High'
            })
        
        # Check for missing CSRF tokens
        if not form.find('input', {'name': ['csrf', 'token', 'csrf_token', '_token']}):
            vulnerabilities.append({
                'type': 'Missing CSRF Protection',
                'name': f'Form {i+1} missing CSRF token',
                'description': 'Form may be vulnerable to Cross-Site Request Forgery attacks.',
                'severity': 'Medium'
            })
    
    return vulnerabilities

def scan_website(url):
    results = []
    
    try:
        # Add http:// if not present
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return [{'type': 'Error', 'name': 'Invalid URL', 'description': 'Please enter a valid URL', 'severity': 'Error'}]
        
        # Make request to get the website
        response = requests.get(url, timeout=10)
        
        # Check for SSL
        if parsed_url.scheme != 'https':
            results.append({
                'type': 'SSL/TLS',
                'name': 'Not using HTTPS',
                'description': 'Website is not using secure HTTPS connection.',
                'severity': 'High'
            })
        
        # Check headers
        results.extend(check_for_header_vulnerabilities(response.headers))
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for forms
        results.extend(check_for_form_vulnerabilities(soup, url))
        
        # Check for cookies
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get('Set-Cookie')
            if 'secure' not in cookies.lower() or 'httponly' not in cookies.lower():
                results.append({
                    'type': 'Cookie Security',
                    'name': 'Insecure Cookies',
                    'description': 'Cookies are missing Secure or HttpOnly flags.',
                    'severity': 'Medium'
                })
        
        # If no vulnerabilities found
        if not results:
            results.append({
                'type': 'Info',
                'name': 'No vulnerabilities found',
                'description': 'No common vulnerabilities were detected.',
                'severity': 'Info'
            })
            
    except requests.exceptions.RequestException as e:
        results.append({
            'type': 'Error',
            'name': 'Connection Error',
            'description': f'Failed to connect to the website: {str(e)}',
            'severity': 'Error'
        })
    
    return results

def generate_plots(df):
    # Plot 1: Severity distribution
    plt.figure(figsize=(8, 6))
    severity_counts = df['severity'].value_counts()
    colors = {'High': 'red', 'Medium': 'orange', 'Low': 'blue', 'Info': 'green', 'Error': 'gray'}
    plt.pie(severity_counts, labels=severity_counts.index, autopct='%1.1f%%', 
            colors=[colors.get(s, 'gray') for s in severity_counts.index])
    plt.title('Vulnerability Severity Distribution')
    
    # Save to buffer
    buf1 = io.BytesIO()
    plt.savefig(buf1, format='png')
    buf1.seek(0)
    plot1 = base64.b64encode(buf1.read()).decode('utf-8')
    plt.close()

    # Plot 2: Vulnerability type distribution
    plt.figure(figsize=(10, 6))
    type_counts = df['type'].value_counts()
    plt.bar(type_counts.index, type_counts.values)
    plt.title('Vulnerability Types')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save to buffer
    buf2 = io.BytesIO()
    plt.savefig(buf2, format='png')
    buf2.seek(0)
    plot2 = base64.b64encode(buf2.read()).decode('utf-8')
    plt.close()
    
    return plot1, plot2

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'})
        
    # Scan the website for vulnerabilities
    results = scan_website(url)
    
    # Convert to DataFrame
    df = pd.DataFrame(results)
    
    # Generate timestamp for filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Generate plots
    plot1, plot2 = generate_plots(df)
    
    # Save plots with absolute paths
    plot1_path = os.path.join(images_dir, f'severity_{timestamp}.png')
    plot2_path = os.path.join(images_dir, f'types_{timestamp}.png')
    
    # Save the plot images
    try:
        with open(plot1_path, 'wb') as f:
            f.write(base64.b64decode(plot1))
        
        with open(plot2_path, 'wb') as f:
            f.write(base64.b64decode(plot2))
        
        print(f"Plots saved at: {plot1_path} and {plot2_path}")
    except Exception as e:
        print(f"Error saving plots: {e}")
    
    # Generate PDF report
    pdf_path = os.path.join(reports_dir, f'vulnerability_report_{timestamp}.pdf')
    
    # Use absolute paths for images in the PDF
    plot1_url = url_for('static', filename=f'images/severity_{timestamp}.png', _external=True)
    plot2_url = url_for('static', filename=f'images/types_{timestamp}.png', _external=True)
    
    html_content = render_template('report.html', 
                                url=url, 
                                results=results, 
                                timestamp=scan_time,
                                plot1=plot1_url,
                                plot2=plot2_url)
    
    # PDF generation options
    options = {
        'page-size': 'A4',
        'margin-top': '20mm',
        'margin-right': '20mm',
        'margin-bottom': '20mm',
        'margin-left': '20mm',
        'encoding': 'UTF-8',
        'no-outline': None,
        'enable-local-file-access': None
    }
    
    # Generate PDF
    pdf_url = None
    if config is not None:
        try:
            pdfkit.from_string(html_content, pdf_path, options=options, configuration=config)
            if os.path.exists(pdf_path):
                pdf_url = f'/download/{timestamp}'
                print(f"PDF generated successfully at {pdf_path}")
            else:
                print("PDF file was not created")
        except Exception as e:
            print(f"Error generating PDF: {e}")
    else:
        print("PDF generation disabled - wkhtmltopdf not configured")
    
    return render_template('results.html', 
                        url=url, 
                        results=results, 
                        plot1=plot1, 
                        plot2=plot2,
                        scan_time=scan_time,
                        pdf_url=pdf_url)

@app.route('/download/<timestamp>')
def download(timestamp):
    try:
        # Use absolute path for PDF file
        pdf_filename = f'vulnerability_report_{timestamp}.pdf'
        pdf_path = os.path.join(reports_dir, pdf_filename)
        
        if os.path.exists(pdf_path):
            try:
                # Add response headers for better browser handling
                response = send_file(
                    pdf_path,
                    mimetype='application/pdf',
                    as_attachment=True,
                    attachment_filename=pdf_filename,  # Using attachment_filename instead of download_name
                    cache_timeout=0  # Prevent caching
                )
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response
            except Exception as e:
                print(f"Error sending file: {e}")
                return str(e), 500
        else:
            print(f"PDF file not found at: {pdf_path}")
            return "PDF report not found", 404
    except Exception as e:
        print(f"Error in download route: {e}")
        return f"Error downloading report: {str(e)}", 500

if __name__ == '__main__':
    # Ensure the app can handle larger files
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.run(debug=True)
