# Vulnerability Scanner

A comprehensive port scanner with vulnerability detection and security recommendations. This tool scans target hosts for open ports, identifies potential security vulnerabilities, and provides actionable recommendations for improving security posture.

## Features

- **Port Scanning**: Basic and version detection scanning using Nmap
- **Real-time Vulnerability Detection**: Uses online APIs (NVD, CVE Details) to find current vulnerabilities
- **Risk Assessment**: Categorizes vulnerabilities by severity (Critical, High, Medium, Low) based on CVSS scores
- **Security Recommendations**: Provides specific action items and alternative services
- **Version Analysis**: Cross-references detected software versions with live vulnerability databases
- **Modern UI**: Clean, responsive interface built with React and Tailwind CSS

## Architecture

- **Frontend**: React.js with Tailwind CSS
- **Backend**: FastAPI with Python
- **Vulnerability Data**: Real-time online APIs (NVD, CVE Details)
- **Scanning Engine**: Python-Nmap integration

## Prerequisites

- Node.js (v14 or higher)
- Python 3.8 or higher
- Nmap installed on your system

### Installing Nmap

**Windows:**

```bash
# Using Chocolatey
choco install nmap

# Or download from https://nmap.org/download.html
```

**macOS:**

```bash
brew install nmap
```

**Linux:**

```bash
# Ubuntu/Debian
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap
```

## Installation

1. **Clone the repository:**

```bash
git clone <repository-url>
cd vuln-scanner
```

2. **Install dependencies:**

```bash
# Install frontend dependencies
npm install

# Install backend dependencies
pip install -r src/backend/requirements.txt
```

## Running the Application

### Quick Start (Recommended)

```bash
# Start all services with one command
python start.py
```

This will automatically:

- Start the backend API server
- Start the frontend development server
- Check all dependencies
- Open the application at `http://localhost:3000`

### Manual Start

If you prefer to start services individually:

```bash
# Terminal 1: Start backend
cd src/backend
python -m uvicorn main:app --reload --port 8000

# Terminal 2: Start frontend
npm start
```

### Stop Services

```bash
# Stop all services
python stop.py
```

## Usage

1. **Open the application** in your browser at `http://localhost:3000`
2. **Enter a target** (IP address or domain name)
3. **Select scan type**:
   - **Basic**: Quick port scan
   - **Version Detection**: Detailed service and version detection
4. **Click Scan** to start the vulnerability assessment
5. **Review results** including:
   - Open ports and services
   - Risk summary with vulnerability counts
   - Detailed vulnerability information
   - Security recommendations
   - Alternative service suggestions

## API Endpoints

- `POST /api/scan` - Perform vulnerability scan
- `GET /api/vulnerabilities` - Get all vulnerabilities from database
- `GET /api/recommendations/{port}` - Get recommendations for specific port

## Database Schema

The application uses SQLite with the following tables:

- **ports**: Port numbers, services, and descriptions
- **vulnerabilities**: CVE data, severity, affected versions
- **recommendations**: Security recommendations and alternatives
- **service_versions**: Version-specific vulnerability patterns

## Security Features

### Vulnerability Detection

- CVE database integration
- CVSS scoring
- Version-specific vulnerability matching
- Severity classification

### Recommendations

- Actionable security improvements
- Alternative service suggestions
- Priority-based recommendations
- Detailed implementation guidance

### Risk Assessment

- Real-time risk calculation
- Visual risk indicators
- Comprehensive risk summary

## Example Scans

### Basic Scan

Scans common ports and identifies open services.

### Version Detection Scan

Performs detailed service fingerprinting and version detection, then cross-references with vulnerability database.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Notice

This tool is designed for authorized security testing only. Always ensure you have permission to scan target systems. Unauthorized scanning may violate laws and terms of service.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Troubleshooting

### Common Issues

1. **Nmap not found**: Ensure Nmap is installed and in your PATH
2. **Permission denied**: Some scans may require elevated privileges
3. **Backend connection failed**: Ensure the backend server is running on port 8000
4. **Database errors**: The SQLite database will be created automatically on first run

### Getting Help

- Check the console for error messages
- Ensure all dependencies are installed
- Verify Nmap is working: `nmap --version`
- Check firewall settings if scans fail
