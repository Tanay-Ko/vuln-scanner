# VulnScan Startup Instructions

## Quick Start

### Option 1: Double-Click Method (Easiest)

1. **Double-click** `start_vuln_scanner.bat` to start all services
2. **Double-click** `stop_vuln_scanner.bat` to stop all services

### Option 2: PowerShell Method

1. **Right-click** on `start_vuln_scanner.ps1` → "Run with PowerShell"
2. **Right-click** on `stop_vuln_scanner.ps1` → "Run with PowerShell"

## What the Startup Script Does

The startup script automatically:

1. **🔍 Checks Prerequisites**

   - Verifies Java 21 is installed (for ZAP)
   - Verifies ZAP is installed
   - Verifies Node.js is installed
   - Verifies Python is installed

2. **🛡️ Starts ZAP (Port 8080)**

   - Uses Java 21 instead of Java 8
   - Runs in daemon mode with API enabled
   - Waits for ZAP to be ready

3. **🔧 Starts Backend (Port 8000)**

   - Installs Python dependencies
   - Starts FastAPI server
   - Waits for API to be ready

4. **🌐 Starts Frontend (Port 3000)**
   - Installs npm dependencies (if needed)
   - Starts React development server
   - Waits for frontend to be ready

## Access Points

Once everything is running:

- **🌐 Main Application**: http://localhost:3000
- **🔧 Backend API**: http://localhost:8000
- **📖 API Documentation**: http://localhost:8000/docs
- **🛡️ ZAP API**: http://localhost:8080

## Troubleshooting

### If the script fails:

1. **Check Java Version**

   ```powershell
   java -version
   ```

   Should show Java 21, not Java 8

2. **Check if ports are in use**

   ```powershell
   netstat -an | findstr ":3000 :8000 :8080"
   ```

3. **Manual startup** (if script fails):

   ```powershell
   # Terminal 1: Start ZAP
   cd "C:\Program Files\ZAP\Zed Attack Proxy"
   "C:\Program Files\Eclipse Adoptium\jdk-21.0.8.9-hotspot\bin\java.exe" -Xmx512m -jar zap-2.16.1.jar -daemon -port 8080 -config api.disablekey=true

   # Terminal 2: Start Backend
   python start_backend.py

   # Terminal 3: Start Frontend
   npm start
   ```

### Common Issues:

- **"Java version error"**: Make sure Java 21 is installed and the path in the script is correct
- **"Port already in use"**: Stop other services using ports 3000, 8000, or 8080
- **"ZAP not starting"**: Check if ZAP is installed in the correct location
- **"Node.js not found"**: Install Node.js from https://nodejs.org

## File Structure

```
vuln-scanner/
├── start_vuln_scanner.ps1    # Main startup script
├── start_vuln_scanner.bat    # Batch wrapper for startup
├── stop_vuln_scanner.ps1     # Shutdown script
├── stop_vuln_scanner.bat     # Batch wrapper for shutdown
├── start_backend.py          # Backend startup (used by main script)
└── STARTUP_INSTRUCTIONS.md   # This file
```

## Notes

- The script will open separate terminal windows for each service
- Use Ctrl+C in each terminal to stop individual services
- The shutdown script will attempt to stop all services automatically
- All services must be running for the scanner to work properly
