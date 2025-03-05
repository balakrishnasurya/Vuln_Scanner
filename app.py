from flask import Flask, render_template, jsonify, request, send_file, url_for, redirect, flash, abort
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
from datetime import datetime, timedelta
import pdfkit
import sys
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from forms import LoginForm, RegistrationForm
from models import db, User, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-goes-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///websecurity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize SQLAlchemy
db.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Create all database tables
with app.app_context():
    db.create_all()

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

@app.context_processor
def inject_datetime():
    return dict(datetime=datetime)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user)
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'})
        
    # Scan the website for vulnerabilities
    results = scan_website(url)
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Calculate severity distribution and vulnerability types
    df = pd.DataFrame(results)
    severity_dist = df['severity'].value_counts().to_dict()
    vulnerability_types = df['type'].value_counts().to_dict()
    
    # Generate timestamp for report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Generate PDF report
    reports_dir = os.path.join(app.static_folder, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f'vulnerability_report_{timestamp}.pdf')
    
    # Generate HTML for PDF
    html_content = render_template('report.html', 
                                url=url, 
                                results=results, 
                                timestamp=scan_time)
    
    # Generate PDF with options
    pdf_url = None
    if config is not None:
        try:
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
            pdfkit.from_string(html_content, pdf_path, options=options, configuration=config)
            if os.path.exists(pdf_path):
                pdf_url = f'/download/{timestamp}'
        except Exception as e:
            print(f"Error generating PDF: {e}")
    
    # Create scan result record
    scan_result = ScanResult(
        url=url,
        results=results,
        severity_distribution=severity_dist,
        vulnerability_distribution=vulnerability_types,
        user_id=current_user.id,
        report_path=pdf_path if pdf_url else None
    )
    
    # Save to database
    db.session.add(scan_result)
    db.session.commit()
    
    return render_template('results.html', 
                        url=url, 
                        results=results,
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=form.remember.data)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('dashboard')
        return redirect(next_page)
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    date_range = request.args.get('date', 'all')
    severity = request.args.get('severity', 'all')
    
    # Base query
    query = ScanResult.query.filter_by(user_id=current_user.id)
    
    # Apply date filter
    if date_range == 'today':
        query = query.filter(ScanResult.timestamp >= datetime.today().date())
    elif date_range == 'week':
        query = query.filter(ScanResult.timestamp >= datetime.today().date() - timedelta(days=7))
    elif date_range == 'month':
        query = query.filter(ScanResult.timestamp >= datetime.today().date() - timedelta(days=30))
    
    # Apply severity filter
    if severity != 'all':
        query = query.filter(ScanResult.severity_counts.like(f'%{severity}%'))
    
    # Paginate results
    pagination = query.order_by(ScanResult.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('history.html', scans=pagination.items, pagination=pagination)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get statistics for the dashboard
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    
    # Count vulnerabilities by severity for current user
    severity_counts = {
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    recent_scans = ScanResult.query.filter_by(user_id=current_user.id)\
        .order_by(ScanResult.timestamp.desc())\
        .limit(5).all()
        
    for scan in recent_scans:
        severity_dist = scan.severity_distribution
        severity_counts['high'] += severity_dist.get('High', 0)
        severity_counts['medium'] += severity_dist.get('Medium', 0)
        severity_counts['low'] += severity_dist.get('Low', 0)
    
    return render_template('dashboard.html',
                         total_scans=total_scans,
                         high_severity=severity_counts['high'],
                         medium_severity=severity_counts['medium'],
                         low_severity=severity_counts['low'],
                         recent_scans=recent_scans,
                         has_data=bool(total_scans))

@app.route('/view_scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        abort(403)
    return render_template('results.html',
                         url=scan.url,
                         results=scan.results,
                         scan_time=scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/download_report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        abort(403)
    if not scan.report_path or not os.path.exists(scan.report_path):
        flash('Report not found', 'error')
        return redirect(url_for('history'))
    return send_file(scan.report_path,
                    mimetype='application/pdf',
                    as_attachment=True,
                    attachment_filename=f'vulnerability_report_{scan.timestamp:%Y%m%d_%H%M%S}.pdf')

@app.route('/export')
@login_required
def export_data():
    format = request.args.get('format', 'csv')
    date_range = request.args.get('date', 'all')
    severity = request.args.get('severity', 'all')
    
    # Base query
    query = ScanResult.query.filter_by(user_id=current_user.id)
    
    # Apply date filter
    if date_range == 'today':
        query = query.filter(ScanResult.timestamp >= datetime.today().date())
    elif date_range == 'week':
        query = query.filter(ScanResult.timestamp >= datetime.today().date() - timedelta(days=7))
    elif date_range == 'month':
        query = query.filter(ScanResult.timestamp >= datetime.today().date() - timedelta(days=30))
    
    # Apply severity filter
    if severity != 'all':
        query = query.filter(ScanResult.severity_counts.like(f'%{severity}%'))
    
    scans = query.order_by(ScanResult.timestamp.desc()).all()
    
    # Create DataFrame
    data = []
    for scan in scans:
        severity_dist = scan.severity_distribution
        row = {
            'Date': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'URL': scan.url,
            'Total Issues': len(scan.results),
            'High Severity': severity_dist.get('High', 0),
            'Medium Severity': severity_dist.get('Medium', 0),
            'Low Severity': severity_dist.get('Low', 0)
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    
    # Generate CSV
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        attachment_filename=f'scan_history_{datetime.now():%Y%m%d_%H%M%S}.csv'
    )

if __name__ == '__main__':
    # Ensure the app can handle larger files
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
    app.run(debug=True)
