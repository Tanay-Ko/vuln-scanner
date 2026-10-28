#!/usr/bin/env python3
"""
Stop script for VulnScan
Stops all running services
"""
import subprocess
import os


def stop_processes_by_port(port, service_name):
    """Stop processes running on a specific port"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run([
                'netstat', '-ano', '-p', 'tcp'
            ], capture_output=True, text=True, check=True)
            stopped = False
            for line in result.stdout.splitlines():
                parts = line.split()
                if (
                    len(parts) >= 5
                    and parts[0].upper() == 'TCP'
                    and parts[3].upper() == 'LISTENING'
                    and parts[1].rsplit(':', 1)[-1] == str(port)
                    and parts[4].isdigit()
                ):
                    pid = parts[4]
                    subprocess.run(
                        ['taskkill', '/F', '/PID', pid],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    print(f"[OK] Stopped {service_name} (PID: {pid})")
                    stopped = True
            if not stopped:
                print(f"[INFO] {service_name} is not running on port {port}")
        else:  # Linux/Mac
            result = subprocess.run(
                ['lsof', '-tiTCP:' + str(port), '-sTCP:LISTEN'],
                capture_output=True,
                text=True,
            )
            if result.returncode not in (0, 1):
                raise subprocess.CalledProcessError(
                    result.returncode,
                    result.args,
                    output=result.stdout,
                    stderr=result.stderr,
                )
            for pid in result.stdout.splitlines():
                if pid.isdigit():
                    subprocess.run(['kill', pid], check=True)
                    print(f"[OK] Stopped {service_name} (PID: {pid})")
            if not result.stdout.strip():
                print(f"[INFO] {service_name} is not running on port {port}")
    except FileNotFoundError as e:
        print(f"[WARNING] Could not stop {service_name}: required command not found ({e})")
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or str(e)).strip()
        print(f"[WARNING] Could not stop {service_name}: {detail}")
    except OSError as e:
        print(f"[WARNING] Could not stop {service_name}: {e}")

def main():
    """Main stop function"""
    print("[INFO] Stopping VulnScan services")
    print("=" * 30)
    
    # Stop services by port
    stop_processes_by_port(3000, "Frontend")
    stop_processes_by_port(8000, "Backend")
    
    print("[OK] Shutdown complete")

if __name__ == "__main__":
    main()
