import subprocess
import sys
import os

def install_requirements():
    print("Installing core dependencies...")
    # Fix for markupsafe - Flask 1.1.4 needs an older version
    subprocess.check_call([sys.executable, "-m", "pip", "install", "markupsafe==2.0.1"])
    
    # Install Flask and Werkzeug with compatible versions
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Flask==1.1.4", "Werkzeug==1.0.1"])
    
    # Clean install of numpy and pandas for compatibility with Python 3.11
    print("Installing compatible numpy...")
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", "numpy", "pandas"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy==1.24.3", "--only-binary=:all:"])
    
    print("Installing compatible pandas...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas==1.5.3", "--only-binary=:all:"])
    
    print("Installing matplotlib from pre-built wheel...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib==3.7.2", "--only-binary=:all:"])
    
    print("Installing pdfkit for PDF generation...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pdfkit==1.0.0"])
    
    print("Installing remaining requirements...")
    # Use --no-deps to avoid reinstalling packages we just installed with specific options
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--no-deps"])
    
    print("\nAll dependencies installed successfully!")
    print("\nNote: To generate PDF reports, you need to install wkhtmltopdf:")
    print("Download from: https://wkhtmltopdf.org/downloads.html")

def check_imports():
    print("\nVerifying key imports...")
    try:
        import flask
        from flask import Flask
        print(f"✓ Flask imported successfully (version {flask.__version__})")
    except ImportError as e:
        print(f"✗ Flask import error: {e}")
        print("  Try installing markupsafe==2.0.1 before flask: pip install markupsafe==2.0.1")
    
    try:
        import werkzeug
        print(f"✓ Werkzeug imported successfully (version {werkzeug.__version__})")
    except ImportError as e:
        print(f"✗ Werkzeug import error: {e}")
    
    try:
        import numpy as np
        print(f"✓ NumPy imported successfully (version {np.__version__})")
    except ImportError as e:
        print(f"✗ NumPy import error: {e}")
    
    try:
        import pandas as pd
        print(f"✓ Pandas imported successfully (version {pd.__version__})")
    except ImportError as e:
        print(f"✗ Pandas import error: {e}")
        print("  Try reinstalling compatible numpy and pandas versions")
    except ValueError as e:
        print(f"✗ Pandas version error: {e}")
        print("  Try reinstalling numpy first, then pandas")
    
    try:
        import matplotlib
        print(f"✓ Matplotlib imported successfully (version {matplotlib.__version__})")
    except ImportError as e:
        print(f"✗ Matplotlib import error: {e}")

def run_app():
    print("\nAttempting to run the app...")
    try:
        subprocess.check_call([sys.executable, "app.py"])
    except subprocess.CalledProcessError:
        print("\n✗ Failed to run app.py. See error above.")
        sys.exit(1)

if __name__ == "__main__":
    print("Vulnerability Dashboard Setup Utility")
    print("====================================\n")
    
    # Ask if user wants to install dependencies
    install = input("Install compatible dependencies? (y/n): ").lower()
    if install == 'y':
        install_requirements()
    
    # Always check imports
    check_imports()
    
    # Ask if user wants to run the app
    run = input("\nRun the application? (y/n): ").lower()
    if run == 'y':
        run_app()
