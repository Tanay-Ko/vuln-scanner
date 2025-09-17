import nmap 
import json
from urllib.parse import urlparse
from vulnerability_api import OnlineVulnerabilityService


def _is_url_with_path(target: str) -> bool:
    try:
        parsed = urlparse(target)
        # If no scheme, try to interpret as http for detection purposes
        if not parsed.scheme:
            parsed = urlparse("http://" + target)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return bool(parsed.path and parsed.path != "/")
        return False
    except Exception:
        return False


def _run_zap_scan(url: str, time_limit: int = None):
    """Run a lightweight OWASP ZAP scan against a specific URL path using ZAP's REST API.
    Requires ZAP to be running as a daemon on localhost:8080.
    Returns a dict with findings or an error message.
    """
    import requests
    import time
    
    zap_api_url = "http://localhost:8080"
    
    try:
        # Check if ZAP is running
        try:
            response = requests.get(f"{zap_api_url}/JSON/core/view/version/", timeout=5)
            if response.status_code != 200:
                return { 
                    "error": "ZAP API not accessible. Make sure ZAP is running on localhost:8080. " +
                            "Start ZAP with: java -jar zap-2.16.1.jar -daemon -port 8080 -config api.disablekey=true"
                }
        except requests.exceptions.ConnectionError:
            return { 
                "error": "Cannot connect to ZAP API on localhost:8080. " +
                        "Please ensure ZAP is running. Start it with: " +
                        "java -jar zap-2.16.1.jar -daemon -port 8080 -config api.disablekey=true"
            }
        except requests.exceptions.RequestException as e:
            return { 
                "error": f"ZAP API connection failed: {str(e)}. " +
                        "Make sure ZAP is running on localhost:8080"
            }
        
        # Start a new session
        session_name = f"scan_{int(time.time())}"
        try:
            session_response = requests.get(f"{zap_api_url}/JSON/core/action/newSession/?name={session_name}", timeout=10)
            if session_response.status_code != 200:
                return { "error": f"Failed to create ZAP session: {session_response.text}" }
        except requests.exceptions.RequestException as e:
            return { "error": f"Failed to create ZAP session: {str(e)}" }
        
        # Access the target URL
        try:
            access_response = requests.get(f"{zap_api_url}/JSON/core/action/accessUrl/?url={url}", timeout=10)
            if access_response.status_code != 200:
                return { "error": f"Failed to access target URL: {access_response.text}" }
        except requests.exceptions.RequestException as e:
            return { "error": f"Failed to access target URL: {str(e)}" }
        
        # Wait a moment for the page to load
        time.sleep(2)
        
        # Run a quick spider scan (very limited scope)
        try:
            spider_response = requests.get(f"{zap_api_url}/JSON/spider/action/scan/?url={url}&maxChildren=2&recurse=false&maxDepth=1", timeout=10)
            if spider_response.status_code != 200:
                return { "error": f"Failed to start spider scan: {spider_response.text}" }
            spider_data = spider_response.json()
            spider_id = spider_data.get('scan')
            if not spider_id:
                return { "error": f"Spider scan failed to start: {spider_data}" }
        except requests.exceptions.RequestException as e:
            return { "error": f"Failed to start spider scan: {str(e)}" }
        
        # Calculate time limits based on user input - much shorter for faster results
        if time_limit:
            spider_time = min(10, time_limit // 6)  # Use 1/6 of time for spider, max 10 seconds
            active_scan_time = min(20, time_limit - spider_time - 5)  # Use remaining time minus buffer, max 20 seconds
        else:
            spider_time = 10  # Default 10 seconds
            active_scan_time = 20  # Default 20 seconds
        
        # Wait for spider to complete
        max_wait = spider_time
        wait_time = 0
        while wait_time < max_wait:
            try:
                status = requests.get(f"{zap_api_url}/JSON/spider/view/status/?scanId={spider_id}", timeout=5).json().get('status')
                if status == '100':
                    break
            except:
                break  # If we can't get status, assume it's done
            time.sleep(2)
            wait_time += 2
        
        # Run a quick active scan (limited to common vulnerabilities)
        try:
            active_scan_response = requests.get(f"{zap_api_url}/JSON/ascan/action/scan/?url={url}&scanPolicyName=Default Policy&maxResults=50", timeout=10)
            if active_scan_response.status_code != 200:
                return { "error": f"Failed to start active scan: {active_scan_response.text}" }
            active_scan_data = active_scan_response.json()
            active_scan_id = active_scan_data.get('scan')
            if not active_scan_id:
                return { "error": f"Active scan failed to start: {active_scan_data}" }
        except requests.exceptions.RequestException as e:
            return { "error": f"Failed to start active scan: {str(e)}" }
        
        # Wait for active scan to complete
        max_wait = active_scan_time
        wait_time = 0
        while wait_time < max_wait:
            try:
                status = requests.get(f"{zap_api_url}/JSON/ascan/view/status/?scanId={active_scan_id}", timeout=5).json().get('status')
                if status == '100':
                    break
            except:
                break  # If we can't get status, assume it's done
            time.sleep(2)
            wait_time += 2
        
        # Force stop any running scans if they're still going
        try:
            requests.get(f"{zap_api_url}/JSON/ascan/action/stop/?scanId={active_scan_id}", timeout=5)
            requests.get(f"{zap_api_url}/JSON/spider/action/stop/?scanId={spider_id}", timeout=5)
        except:
            pass  # Ignore errors when stopping
        
        # Get alerts
        try:
            alerts_response = requests.get(f"{zap_api_url}/JSON/core/view/alerts/?baseurl={url}", timeout=10)
            if alerts_response.status_code != 200:
                return { "error": f"Failed to retrieve alerts: {alerts_response.text}" }
            alerts_data = alerts_response.json().get('alerts', [])
        except requests.exceptions.RequestException as e:
            return { "error": f"Failed to retrieve alerts: {str(e)}" }
        
        findings = []
        for alert in alerts_data:
            findings.append({
                "name": alert.get('name', 'Unknown Issue'),
                "description": alert.get('description', ''),
                "severity": alert.get('risk', 'Info').lower(),
                "confidence": alert.get('confidence', 'Medium'),
                "url": alert.get('url', url),
                "solution": alert.get('solution', ''),
                "reference": alert.get('reference', ''),
                "cweid": alert.get('cweid', ''),
                "wascid": alert.get('wascid', ''),
                "param": alert.get('param', ''),
                "attack": alert.get('attack', ''),
                "evidence": alert.get('evidence', '')
            })
        
        return { "target_url": url, "findings": findings }
        
    except requests.exceptions.RequestException as e:
        return { "error": f"Failed to connect to ZAP API: {str(e)}" }
    except Exception as e:
        return { "error": str(e) }


def run_scan(target: str, scan_type: str = "basic", time_limit: int = None):
    # Handle web-only scan
    if scan_type == "web scan":
        # Ensure a proper URL for ZAP
        parsed = urlparse(target)
        url_for_scan = target if parsed.scheme in ("http", "https") else f"http://{target}"
        zap_results = _run_zap_scan(url_for_scan, time_limit)
        
        return {
            "target": target,
            "scan_time": 0,  # ZAP doesn't provide scan time in our current implementation
            "web_scan": zap_results,
        }
    
    # Handle nmap scans (basic and version detection)
    nm = nmap.PortScanner()

    try:
        # Use aggressive or basic scan directly
        arguments = "-T4 -sV" if scan_type == "version detection" else "-T4 -F"
        
        # Perform scan
        nm.scan(hosts=target, arguments=arguments)
        
        hosts = nm.all_hosts()
        if not hosts:
            return { "error": "No hosts found during scan (may be filtered or protected)" }
        
        host = hosts[0]
        
        if 'tcp' not in nm[host]:
            return { "error": "No open TCP ports found" }
        
        ports = nm[host]['tcp'].items()
        print(nm.command_line())

        results = []
        for port, data in ports:
            results.append({
                "port": port,
                "state": data.get("state"),
                "service": data.get("name"),
                "version": data.get("version"),
                "product": data.get("product"),
            })
        
        # For version detection scans, fetch CVE information
        if scan_type == "version detection":
            vuln_service = OnlineVulnerabilityService()
            
            for result in results:
                if result.get("product") and result.get("version"):
                    print(f"Searching vulnerabilities for {result['product']} {result['version']}")
                    vulnerabilities = vuln_service.search_vulnerabilities_by_product_version(
                        result["product"], 
                        result["version"]
                    )
                    result["cves"] = vulnerabilities
                    
                    # Add security recommendations
                    recommendations = vuln_service.get_recommendations_for_product(
                        result["product"], 
                        result["version"]
                    )
                    result["recommendations"] = recommendations
        
        



        output = {
            "target": target,
            "scan_time": nm.scanstats().get("elapsed"),
            "open_ports": results,
        }

        # If a specific URL path was provided, also run a web path scan via ZAP
        if _is_url_with_path(target):
            # Ensure a proper URL for ZAP
            parsed = urlparse(target)
            url_for_scan = target if parsed.scheme in ("http", "https") else f"http://{target}"
            zap_results = _run_zap_scan(url_for_scan)
            output["web_scan"] = zap_results

        return output

    except Exception as e:
        return { "error": str(e) }




