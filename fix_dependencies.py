import subprocess
import sys

def quick_fix():
    print("Quick Fix: Reinstalling compatible dependencies...")
    
    # Uninstall problematic packages
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", "numpy", "pandas"])
    
    # Install compatible versions in correct order
    subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy==1.24.3", "--only-binary=:all:"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas==1.5.3", "--only-binary=:all:"])
    
    print("\nVerifying fixed imports...")
    try:
        import numpy as np
        print(f"✓ NumPy imported successfully (version {np.__version__})")
        
        import pandas as pd
        print(f"✓ Pandas imported successfully (version {pd.__version__})")
        
        print("\nFix completed successfully! You can now run: python app.py")
    except Exception as e:
        print(f"Error: {e}")
        print("Please run setup_app.py for a complete environment setup.")

if __name__ == "__main__":
    quick_fix()
