#!/usr/bin/env python3
"""
Unified startup script for VulnScan
Starts the local backend and frontend services.
"""
import subprocess
import sys
import time
import requests
from pathlib import Path

def check_port(port, service_name, timeout=30, expected_api_route=None):
    """Check if a service is running on a port"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            health_path = "/openapi.json" if expected_api_route else "/"
            response = requests.get(
                f"http://localhost:{port}{health_path}",
                timeout=2,
            )
            if expected_api_route and response.status_code == 200:
                try:
                    routes = response.json().get("paths", {})
                except ValueError:
                    routes = {}
                if expected_api_route not in routes:
                    print(
                        f"[ERROR] {service_name} on port {port} does not expose "
                        f"{expected_api_route}"
                    )
                    return False
                print(f"[OK] {service_name} is ready on port {port}")
                return True
            if not expected_api_route and response.status_code in [200, 404]:
                print(f"[OK] {service_name} is ready on port {port}")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    print(f"[ERROR] {service_name} failed to start within {timeout} seconds")
    return False

def start_backend():
    """Start the FastAPI backend server"""
    print("[INFO] Starting backend server...")
    backend_dir = Path("src/backend")
    
    # Install requirements if needed
    if not (backend_dir / "requirements.txt").exists():
        print("[ERROR] Backend requirements.txt not found")
        return False
    
    try:
        # Start backend
        process = subprocess.Popen([
            sys.executable, "-m", "uvicorn", "main:app", 
            "--reload", "--port", "8000"
        ], cwd=backend_dir)
        
        # Wait for backend to be ready
        if check_port(8000, "Backend API", expected_api_route="/api/pipeline"):
            return process
        else:
            process.terminate()
            return None
    except Exception as e:
        print(f"[ERROR] Could not start backend: {e}")
        return None

def start_frontend():
    """Start the React frontend"""
    print("[INFO] Starting frontend...")
    
    try:
        # Check if node_modules exists
        if not Path("node_modules").exists():
            print("[INFO] Installing npm dependencies...")
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
        print(f"[ERROR] Could not start frontend: {e}")
        return None

def check_dependencies():
    """Check if required dependencies are available"""
    print("[INFO] Checking dependencies...")
    
    # Check Python
    try:
        python_version = subprocess.check_output([sys.executable, "--version"], text=True).strip()
        print(f"[OK] Python: {python_version}")
    except:
        print("[ERROR] Python not found")
        return False
    
    # Check Node.js
    try:
        node_version = subprocess.check_output(["node", "--version"], text=True).strip()
        print(f"[OK] Node.js: {node_version}")
    except:
        print("[ERROR] Node.js not found")
        return False
    
    # Check npm
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(f"[OK] npm: {result.stdout.strip()}")
        else:
            print("[ERROR] npm not found")
            return False
    except:
        print("[ERROR] npm not found")
        return False
    
    return True

def main():
    """Main startup function"""
    print("[INFO] Starting VulnScan - Vulnerability Scanner")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("[ERROR] Missing required dependencies. Please install Python, Node.js, and npm.")
        return 1
    
    processes = []
    
    try:
        # Start backend
        backend_process = start_backend()
        if backend_process:
            processes.append(("Backend", backend_process))
        else:
            print("[ERROR] Failed to start backend")
            return 1
        
        # Start frontend
        frontend_process = start_frontend()
        if frontend_process:
            processes.append(("Frontend", frontend_process))
        else:
            print("[ERROR] Failed to start frontend")
            return 1
        
        print("\n[OK] VulnScan is ready!")
        print("=" * 50)
        print("Frontend:    http://localhost:3000")
        print("Backend API: http://localhost:8000")
        print("API Docs:    http://localhost:8000/docs")
        print("\nPress Ctrl+C to stop all services")
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down services...")
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1
    
    finally:
        # Clean up processes
        for name, process in processes:
            try:
                print(f"[INFO] Stopping {name}...")
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        print("[INFO] Startup cleanup completed")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
