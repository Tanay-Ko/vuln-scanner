import sqlite3
import json
import requests
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

class VulnerabilityDB:
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.init_database()
        self.populate_initial_data()
    
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create ports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_number INTEGER UNIQUE NOT NULL,
                service_name TEXT NOT NULL,
                description TEXT,
                default_protocol TEXT DEFAULT 'tcp'
            )
        ''')
        
        # Create vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER,
                cve_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                cvss_score REAL,
                affected_versions TEXT,
                fixed_versions TEXT,
                published_date TEXT,
                last_updated TEXT,
                refs TEXT,
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
        ''')
        
        # Create recommendations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER,
                recommendation_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                action_items TEXT,
                alternative_services TEXT,
                priority TEXT DEFAULT 'medium',
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
        ''')
        
        # Create service_versions table for version-specific vulnerabilities
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS service_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER,
                service_name TEXT,
                version_pattern TEXT,
                is_vulnerable BOOLEAN DEFAULT FALSE,
                vulnerability_notes TEXT,
                FOREIGN KEY (port_id) REFERENCES ports (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def populate_initial_data(self):
        """Populate the database with initial vulnerability data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if data already exists
        cursor.execute("SELECT COUNT(*) FROM ports")
        if cursor.fetchone()[0] > 0:
            conn.close()
            return
        
        # Common ports and their vulnerabilities
        ports_data = [
            (21, "FTP", "File Transfer Protocol", "tcp"),
            (22, "SSH", "Secure Shell", "tcp"),
            (23, "Telnet", "Telnet Protocol", "tcp"),
            (25, "SMTP", "Simple Mail Transfer Protocol", "tcp"),
            (53, "DNS", "Domain Name System", "tcp"),
            (80, "HTTP", "Hypertext Transfer Protocol", "tcp"),
            (110, "POP3", "Post Office Protocol v3", "tcp"),
            (143, "IMAP", "Internet Message Access Protocol", "tcp"),
            (443, "HTTPS", "HTTP Secure", "tcp"),
            (993, "IMAPS", "IMAP over SSL/TLS", "tcp"),
            (995, "POP3S", "POP3 over SSL/TLS", "tcp"),
            (3389, "RDP", "Remote Desktop Protocol", "tcp"),
            (5432, "PostgreSQL", "PostgreSQL Database", "tcp"),
            (3306, "MySQL", "MySQL Database", "tcp"),
            (6379, "Redis", "Redis Database", "tcp"),
            (27017, "MongoDB", "MongoDB Database", "tcp"),
            (9200, "Elasticsearch", "Elasticsearch Search Engine", "tcp"),
            (8080, "HTTP-Alt", "Alternative HTTP Port", "tcp"),
            (8443, "HTTPS-Alt", "Alternative HTTPS Port", "tcp"),
            (22, "SSH", "Secure Shell", "udp"),
        ]
        
        # Insert ports
        cursor.executemany(
            "INSERT OR IGNORE INTO ports (port_number, service_name, description, default_protocol) VALUES (?, ?, ?, ?)",
            ports_data
        )
        
        # Get port IDs for foreign key relationships
        cursor.execute("SELECT id, port_number FROM ports")
        port_mapping = {port_num: port_id for port_id, port_num in cursor.fetchall()}
        
        # Sample vulnerabilities data
        vulnerabilities_data = [
            # FTP vulnerabilities
            (port_mapping.get(21), "CVE-2020-15778", "FTP Command Injection", 
             "FTP servers may be vulnerable to command injection attacks", "high", 8.1,
             "All versions", "Latest patched versions", "2020-08-17", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15778"])),
            
            # SSH vulnerabilities
            (port_mapping.get(22), "CVE-2020-14145", "SSH Key Exchange Vulnerability",
             "SSH servers may be vulnerable to key exchange attacks", "medium", 6.5,
             "OpenSSH < 8.3", "OpenSSH 8.3+", "2020-07-01", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14145"])),
            
            # Telnet vulnerabilities
            (port_mapping.get(23), "CVE-2021-44228", "Telnet Log4j Vulnerability",
             "Telnet services using vulnerable Log4j versions", "critical", 10.0,
             "Log4j 2.0-2.14.1", "Log4j 2.15.0+", "2021-12-09", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"])),
            
            # HTTP vulnerabilities
            (port_mapping.get(80), "CVE-2021-44228", "Apache Log4j RCE",
             "Apache web servers vulnerable to Log4j remote code execution", "critical", 10.0,
             "Log4j 2.0-2.14.1", "Log4j 2.15.0+", "2021-12-09", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"])),
            
            # HTTPS vulnerabilities
            (port_mapping.get(443), "CVE-2021-44228", "HTTPS Log4j Vulnerability",
             "HTTPS services vulnerable to Log4j attacks", "critical", 10.0,
             "Log4j 2.0-2.14.1", "Log4j 2.15.0+", "2021-12-09", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"])),
            
            # RDP vulnerabilities
            (port_mapping.get(3389), "CVE-2019-0708", "BlueKeep RDP Vulnerability",
             "Remote Desktop Protocol vulnerable to BlueKeep attack", "critical", 9.8,
             "Windows 7, 2008 R2, 2008", "Patched versions", "2019-05-14", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0708"])),
            
            # MySQL vulnerabilities
            (port_mapping.get(3306), "CVE-2021-44228", "MySQL Log4j Vulnerability",
             "MySQL services vulnerable to Log4j attacks", "critical", 10.0,
             "MySQL with Log4j 2.0-2.14.1", "MySQL with Log4j 2.15.0+", "2021-12-09", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"])),
            
            # Redis vulnerabilities
            (port_mapping.get(6379), "CVE-2021-32761", "Redis Memory Corruption",
             "Redis vulnerable to memory corruption attacks", "high", 7.5,
             "Redis < 6.2.6", "Redis 6.2.6+", "2021-07-15", "2024-01-01",
             json.dumps(["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32761"])),
        ]
        
        # Insert vulnerabilities
        cursor.executemany(
            """INSERT INTO vulnerabilities 
               (port_id, cve_id, title, description, severity, cvss_score, 
                affected_versions, fixed_versions, published_date, last_updated, refs)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            vulnerabilities_data
        )
        
        # Sample recommendations data
        recommendations_data = [
            # FTP recommendations
            (port_mapping.get(21), "security", "Disable FTP or Use SFTP",
             "FTP is inherently insecure. Consider disabling or replacing with SFTP/FTPS",
             json.dumps([
                 "Disable FTP service if not needed",
                 "Use SFTP (SSH File Transfer Protocol) instead",
                 "Implement FTPS (FTP over SSL/TLS) if FTP is required",
                 "Use strong authentication and encryption"
             ]),
             json.dumps(["SFTP", "FTPS", "SCP"]), "high"),
            
            # Telnet recommendations
            (port_mapping.get(23), "security", "Replace Telnet with SSH",
             "Telnet transmits data in plaintext. SSH provides encrypted communication",
             json.dumps([
                 "Disable Telnet service immediately",
                 "Use SSH for remote access",
                 "Configure SSH with key-based authentication",
                 "Disable password authentication for SSH"
             ]),
             json.dumps(["SSH", "RDP (with proper security)", "VPN"]), "critical"),
            
            # HTTP recommendations
            (port_mapping.get(80), "security", "Upgrade to HTTPS",
             "HTTP transmits data in plaintext. HTTPS provides encryption",
             json.dumps([
                 "Redirect all HTTP traffic to HTTPS",
                 "Implement HSTS (HTTP Strict Transport Security)",
                 "Use strong SSL/TLS certificates",
                 "Regularly update web server software"
             ]),
             json.dumps(["HTTPS", "HTTP/2", "HTTP/3"]), "high"),
            
            # RDP recommendations
            (port_mapping.get(3389), "security", "Secure RDP Configuration",
             "RDP can be vulnerable if not properly configured",
             json.dumps([
                 "Enable Network Level Authentication (NLA)",
                 "Use strong passwords and consider 2FA",
                 "Restrict RDP access to specific IP ranges",
                 "Consider using VPN for RDP access",
                 "Keep Windows updated with latest patches"
             ]),
             json.dumps(["VPN + RDP", "Remote Desktop Gateway", "TeamViewer", "AnyDesk"]), "high"),
            
            # Database recommendations
            (port_mapping.get(3306), "security", "Secure MySQL Configuration",
             "Database servers require strong security measures",
             json.dumps([
                 "Change default passwords",
                 "Disable remote root login",
                 "Use SSL/TLS for connections",
                 "Implement database firewall",
                 "Regular security updates"
             ]),
             json.dumps(["PostgreSQL", "MariaDB", "Cloud Database Services"]), "high"),
            
            (port_mapping.get(5432), "security", "Secure PostgreSQL Configuration",
             "PostgreSQL requires proper security configuration",
             json.dumps([
                 "Change default passwords",
                 "Configure pg_hba.conf properly",
                 "Use SSL/TLS connections",
                 "Implement connection pooling",
                 "Regular security updates"
             ]),
             json.dumps(["MySQL", "MariaDB", "Cloud Database Services"]), "high"),
        ]
        
        # Insert recommendations
        cursor.executemany(
            """INSERT INTO recommendations 
               (port_id, recommendation_type, title, description, action_items, alternative_services, priority)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            recommendations_data
        )
        
        # Sample service versions data
        service_versions_data = [
            (port_mapping.get(22), "OpenSSH", "OpenSSH_7.*", True, "Versions 7.x have known vulnerabilities"),
            (port_mapping.get(22), "OpenSSH", "OpenSSH_8.*", False, "Versions 8.x are more secure"),
            (port_mapping.get(80), "Apache", "Apache/2.4.*", True, "Some 2.4.x versions have vulnerabilities"),
            (port_mapping.get(443), "nginx", "nginx/1.18.*", True, "Versions 1.18.x have known issues"),
            (port_mapping.get(3306), "MySQL", "MySQL 5.7.*", True, "MySQL 5.7 is end-of-life"),
            (port_mapping.get(3306), "MySQL", "MySQL 8.0.*", False, "MySQL 8.0 is current and supported"),
        ]
        
        # Insert service versions
        cursor.executemany(
            """INSERT INTO service_versions 
               (port_id, service_name, version_pattern, is_vulnerable, vulnerability_notes)
               VALUES (?, ?, ?, ?, ?)""",
            service_versions_data
        )
        
        conn.commit()
        conn.close()
    
    def analyze_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze open ports for vulnerabilities and provide recommendations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
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
        
        for port_info in open_ports:
            port_num = port_info.get("port")
            service = port_info.get("service", "").lower()
            product = port_info.get("product", "").lower()
            version = port_info.get("version", "").lower()
            
            # Get port information
            cursor.execute("SELECT id, service_name, description FROM ports WHERE port_number = ?", (port_num,))
            port_data = cursor.fetchone()
            
            if not port_data:
                continue
                
            port_id, service_name, description = port_data
            
            # Get vulnerabilities for this port
            cursor.execute("""
                SELECT cve_id, title, description, severity, cvss_score, affected_versions, 
                       fixed_versions, published_date, refs
                FROM vulnerabilities WHERE port_id = ?
            """, (port_id,))
            vulnerabilities = cursor.fetchall()
            
            # Get recommendations for this port
            cursor.execute("""
                SELECT recommendation_type, title, description, action_items, 
                       alternative_services, priority
                FROM recommendations WHERE port_id = ?
            """, (port_id,))
            recommendations = cursor.fetchone()
            
            # Check for version-specific vulnerabilities
            version_vulnerabilities = []
            if product and version:
                cursor.execute("""
                    SELECT service_name, version_pattern, is_vulnerable, vulnerability_notes
                    FROM service_versions WHERE port_id = ? AND service_name LIKE ?
                """, (port_id, f"%{product}%"))
                version_data = cursor.fetchall()
                
                for svc_name, version_pattern, is_vuln, notes in version_data:
                    if is_vuln:
                        version_vulnerabilities.append({
                            "service": svc_name,
                            "pattern": version_pattern,
                            "notes": notes
                        })
            
            # Calculate risk level
            risk_level = "low"
            if vulnerabilities:
                max_cvss = max([v[4] for v in vulnerabilities if v[4] is not None], default=0)
                if max_cvss >= 9.0:
                    risk_level = "critical"
                elif max_cvss >= 7.0:
                    risk_level = "high"
                elif max_cvss >= 4.0:
                    risk_level = "medium"
            
            # Prepare port analysis
            port_analysis = {
                "port": port_num,
                "service": service_name,
                "description": description,
                "risk_level": risk_level,
                "vulnerabilities": [],
                "recommendations": None,
                "version_analysis": version_vulnerabilities
            }
            
            # Add vulnerabilities
            for vuln in vulnerabilities:
                cve_id, title, desc, severity, cvss, affected, fixed, published, refs = vuln
                port_analysis["vulnerabilities"].append({
                    "cve_id": cve_id,
                    "title": title,
                    "description": desc,
                    "severity": severity,
                    "cvss_score": cvss,
                    "affected_versions": affected,
                    "fixed_versions": fixed,
                    "published_date": published,
                    "references": json.loads(refs) if refs else []
                })
                
                # Update risk summary
                analysis_results["risk_summary"][severity] += 1
            
            # Add recommendations
            if recommendations:
                rec_type, rec_title, rec_desc, action_items, alt_services, priority = recommendations
                port_analysis["recommendations"] = {
                    "type": rec_type,
                    "title": rec_title,
                    "description": rec_desc,
                    "action_items": json.loads(action_items) if action_items else [],
                    "alternative_services": json.loads(alt_services) if alt_services else [],
                    "priority": priority
                }
            
            analysis_results["vulnerable_ports"].append(port_analysis)
        
        conn.close()
        return analysis_results
    
    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all vulnerabilities from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT p.port_number, p.service_name, v.cve_id, v.title, v.description,
                   v.severity, v.cvss_score, v.affected_versions, v.fixed_versions,
                   v.published_date, v.refs
            FROM vulnerabilities v
            JOIN ports p ON v.port_id = p.id
            ORDER BY v.cvss_score DESC
        """)
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                "port": row[0],
                "service": row[1],
                "cve_id": row[2],
                "title": row[3],
                "description": row[4],
                "severity": row[5],
                "cvss_score": row[6],
                "affected_versions": row[7],
                "fixed_versions": row[8],
                "published_date": row[9],
                "references": json.loads(row[10]) if row[10] else []
            })
        
        conn.close()
        return vulnerabilities
    
    def get_recommendations(self, port: int) -> List[Dict[str, Any]]:
        """Get recommendations for a specific port"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT r.recommendation_type, r.title, r.description, r.action_items,
                   r.alternative_services, r.priority
            FROM recommendations r
            JOIN ports p ON r.port_id = p.id
            WHERE p.port_number = ?
        """, (port,))
        
        recommendations = []
        for row in cursor.fetchall():
            recommendations.append({
                "type": row[0],
                "title": row[1],
                "description": row[2],
                "action_items": json.loads(row[3]) if row[3] else [],
                "alternative_services": json.loads(row[4]) if row[4] else [],
                "priority": row[5]
            })
        
        conn.close()
        return recommendations
