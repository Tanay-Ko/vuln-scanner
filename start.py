#!/usr/bin/env python3
"""
Unified startup script for VulnScan
Starts all required services: ZAP, Backend, and Frontend
"""
import subprocess
import sys
import os
import time
import requests
import threading
from pathlib import Path

def check_port(port, service_name, timeout=30):
    """Check if a service is running on a port"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"http://localhost:{port}", timeout=2)
            if response.status_code in [200, 404]:  # 404 is OK for some services
                print(f"✅ {service_name} is ready on port {port}")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    print(f"❌ {service_name} failed to start within {timeout} seconds")
    return False

def start_backend():
    """Start the FastAPI backend server"""
    print("🔧 Starting Backend Server...")
    backend_dir = Path("src/backend")
    
    # Install requirements if needed
    if not (backend_dir / "requirements.txt").exists():
        print("❌ Backend requirements.txt not found")
        return False
    
    try:
        # Start backend
        process = subprocess.Popen([
            sys.executable, "-m", "uvicorn", "main:app", 
            "--reload", "--port", "8000"
        ], cwd=backend_dir)
        
        # Wait for backend to be ready
        if check_port(8000, "Backend API"):
            return process
        else:
            process.terminate()
            return None
    except Exception as e:
        print(f"❌ Error starting backend: {e}")
        return None

def start_frontend():
    """Start the React frontend"""
    print("🌐 Starting Frontend...")
    
    try:
        # Check if node_modules exists
        if not Path("node_modules").exists():
            print("📦 Installing npm dependencies...")
            subprocess.run(["npm", "install"], check=True, shell=True)
        
        # Start React app
        process = subprocess.Popen(["npm", "start"], shell=True)
        
        # Wait for frontend to be ready
        if check_port(3000, "Frontend", timeout=60):
            return process
        else:
            process.terminate()
            return None
    except Exception as e:
        print(f"❌ Error starting frontend: {e}")
        return None

def check_dependencies():
    """Check if required dependencies are available"""
    print("🔍 Checking dependencies...")
    
    # Check Python
    try:
        python_version = subprocess.check_output([sys.executable, "--version"], text=True).strip()
        print(f"✅ Python: {python_version}")
    except:
        print("❌ Python not found")
        return False
    
    # Check Node.js
    try:
        node_version = subprocess.check_output(["node", "--version"], text=True).strip()
        print(f"✅ Node.js: {node_version}")
    except:
        print("❌ Node.js not found")
        return False
    
    # Check npm
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(f"✅ npm: {result.stdout.strip()}")
        else:
            print("❌ npm not found")
            return False
    except:
        print("❌ npm not found")
        return False
    
    return True

def main():
    """Main startup function"""
    print("🚀 Starting VulnScan - Vulnerability Scanner")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Missing required dependencies. Please install Python, Node.js, and npm.")
        return 1
    
    processes = []
    
    try:
        # Start backend
        backend_process = start_backend()
        if backend_process:
            processes.append(("Backend", backend_process))
        else:
            print("❌ Failed to start backend")
            return 1
        
        # Start frontend
        frontend_process = start_frontend()
        if frontend_process:
            processes.append(("Frontend", frontend_process))
        else:
            print("❌ Failed to start frontend")
            return 1
        
        print("\n🎉 VulnScan is ready!")
        print("=" * 50)
        print("🌐 Frontend:    http://localhost:3000")
        print("🔧 Backend API: http://localhost:8000")
        print("📖 API Docs:    http://localhost:8000/docs")
        print("\n💡 Press Ctrl+C to stop all services")
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down services...")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    finally:
        # Clean up processes
        for name, process in processes:
            try:
                print(f"🛑 Stopping {name}...")
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        print("✅ All services stopped")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
