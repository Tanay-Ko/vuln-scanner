#!/usr/bin/env python3
"""
Stop script for VulnScan
Stops all running services
"""
import subprocess
import sys
import os

def stop_processes_by_port(port, service_name):
    """Stop processes running on a specific port"""
    try:
        if os.name == 'nt':  # Windows
            # Find processes using the port
            result = subprocess.run([
                'netstat', '-ano', '-p', 'tcp'
            ], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        try:
                            subprocess.run(['taskkill', '/F', '/PID', pid], check=True)
                            print(f"✅ Stopped {service_name} (PID: {pid})")
                        except:
                            pass
        else:  # Linux/Mac
            subprocess.run(['pkill', '-f', f':{port}'], check=True)
            print(f"✅ Stopped {service_name}")
    except:
        print(f"⚠️  Could not stop {service_name}")

def main():
    """Main stop function"""
    print("🛑 Stopping VulnScan Services")
    print("=" * 30)
    
    # Stop services by port
    stop_processes_by_port(3000, "Frontend")
    stop_processes_by_port(8000, "Backend")
    stop_processes_by_port(8080, "ZAP")
    
    # Also try to stop by process name
    try:
        if os.name == 'nt':  # Windows
            subprocess.run(['taskkill', '/F', '/IM', 'node.exe'], capture_output=True)
            subprocess.run(['taskkill', '/F', '/IM', 'python.exe'], capture_output=True)
        else:  # Linux/Mac
            subprocess.run(['pkill', '-f', 'node'], capture_output=True)
            subprocess.run(['pkill', '-f', 'python'], capture_output=True)
    except:
        pass
    
    print("✅ Shutdown complete!")

if __name__ == "__main__":
    main()
