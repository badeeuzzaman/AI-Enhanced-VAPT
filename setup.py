#!/usr/bin/env python3
"""
Kali Linux Compatible Setup Script for AI-Enhanced VAPT Tool
"""

import subprocess
import sys
import os
import platform

def is_kali_linux():
    """Check if running on Kali Linux"""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read().lower()
            return 'kali' in content
    except:
        return False

def run_command(command, description):
    """Run a shell command with error handling"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def setup_venv():
    """Set up Python virtual environment"""
    venv_dir = "vapt_venv"
    
    print("🐍 Setting up Python virtual environment...")
    
    # Create virtual environment
    if not run_command(f"python3 -m venv {venv_dir}", "Creating virtual environment"):
        return None
        
    # Determine the correct pip path
    if os.name == 'nt':  # Windows
        pip_path = os.path.join(venv_dir, "Scripts", "pip")
        activate_cmd = f"{venv_dir}\\Scripts\\activate"
        python_cmd = os.path.join(venv_dir, "Scripts", "python")
    else:  # Linux/Mac
        pip_path = os.path.join(venv_dir, "bin", "pip")
        activate_cmd = f"source {venv_dir}/bin/activate"
        python_cmd = os.path.join(venv_dir, "bin", "python")
    
    return (pip_path, activate_cmd, python_cmd)

def install_dependencies_kali():
    """Install dependencies on Kali Linux"""
    print("🦈 Kali Linux detected - using system packages where possible...")
    
    # Try system packages first
    system_packages = [
        "python3-nmap",
        "python3-requests"
    ]
    
    success = True
    for package in system_packages:
        if run_command(f"sudo apt install -y {package}", f"Installing {package} via apt"):
            print(f"✅ {package} installed via apt")
        else:
            print(f"⚠️  Could not install {package} via apt")
            success = False
            
    return success

def install_dependencies_venv(pip_path):
    """Install dependencies in virtual environment"""
    dependencies = [
        "python-nmap",
        "requests"
    ]
    
    for package in dependencies:
        if not run_command(f"{pip_path} install {package}", f"Installing {package} in virtual environment"):
            return False
    return True

def verify_nmap_installation():
    """Verify nmap is installed on the system"""
    print("🔍 Verifying nmap installation...")
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, check=True)
        print("✅ nmap is installed:")
        print(f"   {result.stdout.splitlines()[0]}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ nmap is not installed or not in PATH")
        print("💡 Installing nmap...")
        if run_command("sudo apt install -y nmap", "Installing nmap"):
            return True
        return False

def verify_python_dependencies():
    """Verify Python dependencies are properly installed"""
    print("🔍 Verifying Python dependencies...")
    
    dependencies = {
        'nmap': 'python3-nmap',
        'requests': 'python3-requests'
    }
    
    missing_deps = []
    for module, package in dependencies.items():
        try:
            __import__(module)
            print(f"✅ {module} is available")
        except ImportError as e:
            print(f"❌ {module} is not available: {e}")
            missing_deps.append(package)
    
    return len(missing_deps) == 0

def create_directories():
    """Create necessary directories"""
    print("📁 Creating directory structure...")
    directories = ['config', 'modules', 'utils']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✅ Created {directory}/ directory")
        else:
            print(f"✅ {directory}/ directory already exists")

def create_required_files():
    """Create required files if they don't exist"""
    print("📄 Creating required files...")
    
    # Create __init__.py files
    init_files = ['config/__init__.py', 'modules/__init__.py', 'utils/__init__.py']
    
    for file_path in init_files:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write('')
            print(f"✅ Created {file_path}")

def main():
    """Main setup function"""
    print("🚀 AI-Enhanced VAPT Tool Setup (Kali Linux Compatible)")
    print("=" * 60)
    
    # Initialize venv_info
    venv_info = None
    
    # Create directories and files
    create_directories()
    create_required_files()
    
    # Check if we're on Kali Linux
    if is_kali_linux():
        print("🦈 Detected Kali Linux environment")
        
        # Option 1: Try system packages
        system_install_success = install_dependencies_kali()
        
        if not system_install_success:
            # Option 2: Use virtual environment
            print("🔄 Falling back to virtual environment installation...")
            venv_info = setup_venv()
            
            if venv_info:
                pip_path, activate_cmd, python_cmd = venv_info
                if install_dependencies_venv(pip_path):
                    print(f"✅ Virtual environment setup complete!")
                    print(f"💡 To activate the virtual environment, run: {activate_cmd}")
                else:
                    print("❌ Virtual environment installation failed")
                    sys.exit(1)
            else:
                print("❌ Virtual environment setup failed")
                sys.exit(1)
    else:
        # Non-Kali Linux - use virtual environment
        print("💻 Non-Kali Linux detected - using virtual environment")
        venv_info = setup_venv()
        
        if venv_info:
            pip_path, activate_cmd, python_cmd = venv_info
            if install_dependencies_venv(pip_path):
                print(f"✅ Virtual environment setup complete!")
                print(f"💡 To activate the virtual environment, run: {activate_cmd}")
            else:
                print("❌ Virtual environment installation failed")
                sys.exit(1)
        else:
            print("❌ Virtual environment setup failed")
            sys.exit(1)
    
    # Verify nmap installation
    if not verify_nmap_installation():
        print("⚠️  nmap not found. Port scanning will not work.")
        response = input("Continue anyway? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("Setup cancelled.")
            sys.exit(1)
    
    # Verify Python dependencies
    if not verify_python_dependencies():
        print("⚠️  Some Python dependencies are missing.")
        response = input("Continue anyway? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("Setup cancelled.")
            sys.exit(1)
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Get your DeepSeek API key from https://platform.deepseek.com/")
    
    if is_kali_linux() and venv_info is None:
        print("2. Run: python3 main.py")
    else:
        if venv_info:
            pip_path, activate_cmd, python_cmd = venv_info
            print("2. Activate virtual environment and run:")
            print(f"   {activate_cmd}")
            print("   python3 main.py")
        else:
            print("2. Run: python3 main.py")
    
    print("\n3. Follow the interactive prompts")
    print("\n⚠️  Important: Only use this tool on systems you own or have explicit permission to test!")
    print("   This tool is for educational and authorized security testing only.")

if __name__ == "__main__":
    main()