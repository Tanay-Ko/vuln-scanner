from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import time
from scanner import run_scan
from vulnerability_api import OnlineVulnerabilityService  

app = FastAPI()

# Initialize online vulnerability service
vuln_service = OnlineVulnerabilityService()

# Allow frontend requests from localhost:3000 (React dev server)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    scanType: Optional[str] = "basic"
    timeLimit: Optional[int] = None

@app.post("/api/scan")
async def scan_endpoint(request: ScanRequest):
    results = run_scan(request.target, request.scanType, request.timeLimit)
    
    # If scan was successful and we have open ports, analyze vulnerabilities
    if results.get("open_ports") and not results.get("error"):
        # Filter to only open ports for vulnerability analysis
        open_ports = [port for port in results["open_ports"] if port.get("state") == "open"]
        if open_ports and request.scanType == "version detection":
            # Only analyze vulnerabilities for version detection scans
            enhanced_results = await analyze_vulnerabilities_online(open_ports)
            results["vulnerability_analysis"] = enhanced_results
            
            # Update the individual ports with CVE data from the analysis
            for port_analysis in enhanced_results.get("vulnerable_ports", []):
                port_num = port_analysis["port"]
                # Find the corresponding port in results and update it
                for port in results["open_ports"]:
                    if port["port"] == port_num:
                        port["cves"] = port_analysis["vulnerabilities"]
                        port["recommendations"] = port_analysis["recommendations"]
                        break
    
    return results

async def analyze_vulnerabilities_online(open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze vulnerabilities using online APIs"""
    analysis_results = {
        "total_ports": len(open_ports),
        "vulnerable_ports": [],
        "recommendations": [],
        "risk_summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
    }
    
    # Track unique vulnerabilities to avoid double counting
    seen_vulnerabilities = set()
    
    for port_info in open_ports:
        port_num = port_info.get("port")
        service = port_info.get("service", "").lower()
        product = port_info.get("product", "").lower()
        version = port_info.get("version", "").lower()
        
        # Only analyze if we have product and version information
        if not product or not version:
            continue
        
        print(f"Analyzing vulnerabilities for {product} {version} on port {port_num}")
        
        # Search for vulnerabilities
        vulnerabilities = vuln_service.search_vulnerabilities_by_product_version(product, version)
        print(f"Found {len(vulnerabilities)} vulnerabilities for {product} {version}")
        
        # Get recommendations
        recommendations = vuln_service.get_recommendations_for_product(product, version)
        
        # Calculate risk level
        risk_level = "low"
        if vulnerabilities:
            max_cvss = max([v.get('cvss_score', 0) for v in vulnerabilities], default=0)
            if max_cvss >= 9.0:
                risk_level = "critical"
            elif max_cvss >= 7.0:
                risk_level = "high"
            elif max_cvss >= 4.0:
                risk_level = "medium"
        
        # Prepare port analysis
        port_analysis = {
            "port": port_num,
            "service": service,
            "product": product,
            "version": version,
            "risk_level": risk_level,
            "vulnerabilities": vulnerabilities,  # Show all vulnerabilities
            "recommendations": recommendations
        }
        
        # Count vulnerabilities by severity (only count unique vulnerabilities)
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if cve_id and cve_id not in seen_vulnerabilities:
                seen_vulnerabilities.add(cve_id)
                severity = vuln.get('severity', 'low')
                if severity in analysis_results["risk_summary"]:
                    analysis_results["risk_summary"][severity] += 1
        
        analysis_results["vulnerable_ports"].append(port_analysis)
        
        # Add a small delay to avoid rate limiting
        time.sleep(0.5)
    
    print(f"Final analysis results: {analysis_results['risk_summary']}")
    print(f"Total vulnerable ports: {len(analysis_results['vulnerable_ports'])}")
    print(f"Unique vulnerabilities found: {len(seen_vulnerabilities)}")
    
    return analysis_results

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    """Get vulnerability information (placeholder for online service)"""
    return {"message": "Use version detection scan to get real-time vulnerability data"}

@app.get("/api/recommendations/{port}")
async def get_recommendations(port: int):
    """Get recommendations for a specific port"""
    return {"message": "Use version detection scan to get recommendations for detected services"}
  
