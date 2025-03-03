# Vulnerability Dashboard

A web application to visualize and analyze web application vulnerabilities.

## Setup Instructions

### Option 1: Standard Setup (Recommended)

Use our setup utility to install compatible dependencies and verify imports:

```
python setup_app.py
```

### Option 2: Manual Setup

If you prefer to install dependencies manually:

1. Install MarkupSafe compatible with Flask 1.1.4:
   ```
   pip install markupsafe==2.0.1
   ```

2. Install the specific compatible versions:
   ```
   pip install Flask==1.1.4 Werkzeug==1.0.1
   ```

3. Install compatible versions of numpy, pandas, and matplotlib:
   ```
   pip install numpy==1.24.3 pandas==1.5.3 matplotlib==3.7.2 --only-binary=:all:
   ```

4. Install remaining dependencies:
   ```
   pip install -r requirements.txt --no-deps
   ```

5. Run the Flask application:
   ```
   python app.py
   ```

## Troubleshooting

### Werkzeug Import Error
If you see `ImportError: cannot import name 'url_quote' from 'werkzeug.urls'`:
- Ensure you have Werkzeug 1.0.1 installed: `pip install Werkzeug==1.0.1`
- Ensure you have Flask 1.1.4 installed: `pip install Flask==1.1.4`

### Flask Import Error
If you see `ImportError: cannot import name 'soft_unicode' from 'markupsafe'`:
- Install an older version of MarkupSafe: `pip install markupsafe==2.0.1`

### Pandas/NumPy Compatibility Issues
If you see `ValueError: numpy.dtype size changed, may indicate binary incompatibility`:
1. Uninstall both packages: `pip uninstall -y numpy pandas`
2. Install compatible versions for Python 3.11:
   ```
   pip install numpy==1.24.3 pandas==1.5.3 --only-binary=:all:
   ```

## Features

- Interactive dashboard with vulnerability statistics
- Filtering and searching capabilities
- Visual representation of vulnerability severity
- Detailed vulnerability listing
- PDF generation of vulnerability reports

## Project Structure

- `app.py` - Flask backend application
- `results.csv` - Vulnerability scan data
- `templates/` - HTML templates
- `static/` - CSS, JavaScript and other static files
- `requirements.txt` - Python dependencies
- `setup_app.py` - Helper script for easy setup
