# Web Security Scanner

A comprehensive web security scanning tool that helps identify common vulnerabilities and security misconfigurations in websites.

## Features

- **Security Header Analysis**: Checks for missing or misconfigured security headers
- **SSL/TLS Verification**: Validates HTTPS implementation
- **Form Security**: Detects insecure form submissions and missing CSRF tokens
- **Cookie Security**: Analyzes cookie security configurations
- **Visual Reports**: Interactive charts and detailed vulnerability analysis
- **PDF Report Generation**: Exportable PDF reports for documentation
- **Modern UI**: Clean, responsive interface with Google Material Design influences

## Installation

### Prerequisites

1. Python 3.8 or higher
2. pip (Python package installer)
3. wkhtmltopdf (for PDF generation)

### Setup Instructions

1. Clone the repository:
```bash
git clone [your-repository-url]
cd [repository-name]
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# For Windows:
.venv\Scripts\activate
# For Unix/MacOS:
source .venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Install wkhtmltopdf for PDF generation:
   - Download the installer: [wkhtmltox-0.12.6-1.msvc2015-win64.exe](https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6-1/wkhtmltox-0.12.6-1.msvc2015-win64.exe)
   - Run the installer
   - Choose the default installation path (C:\Program Files\wkhtmltopdf)
   - Ensure "Add to system PATH" is selected during installation
   - Restart your terminal/command prompt after installation

### Running the Application

1. Start the Flask server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

## Usage

1. Enter the target website URL in the scan form
2. Click "Scan Website" to initiate the security analysis
3. View the results, including:
   - Vulnerability severity distribution
   - Types of vulnerabilities found
   - Detailed findings table
4. Download or print the PDF report for documentation

## Features in Detail

### Security Checks

- **Security Headers**
  - HSTS (HTTP Strict Transport Security)
  - Content Security Policy (CSP)
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection

- **Form Security**
  - HTTPS submission verification
  - CSRF token presence
  - Secure form configuration

- **Cookie Security**
  - Secure flag verification
  - HttpOnly flag checking
  - Cookie security best practices

### Reporting

- Interactive charts and visualizations
- Severity-based categorization
- Detailed vulnerability descriptions
- Exportable PDF reports
- Print-friendly report formatting

## Project Structure

```
project/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── static/               # Static assets
│   ├── css/             # Stylesheets
│   ├── images/          # Generated charts
│   └── reports/         # Generated PDF reports
├── templates/           # HTML templates
│   ├── index.html      # Main scan page
│   ├── results.html    # Scan results page
│   └── report.html     # PDF report template
└── .gitignore          # Git ignore file
```

## Troubleshooting

1. **PDF Generation Issues**
   - Verify wkhtmltopdf is properly installed
   - Check system PATH includes wkhtmltopdf
   - Restart the application after installation
   - Ensure write permissions in the reports directory

2. **Scan Failures**
   - Check target URL format
   - Verify internet connectivity
   - Ensure target site is accessible
   - Check console for error messages

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask web framework
- Matplotlib for data visualization
- wkhtmltopdf for PDF generation
- Font Awesome for icons
