import React from 'react';

function VersionScanResults({ results }) {
  if (!results || !results.open_ports) {
    return null;
  }



  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-900 text-white border-red-900 dark:bg-red-900 dark:text-white dark:border-red-900';
      case 'high':
        return 'bg-red-600 text-white border-red-600 dark:bg-red-600 dark:text-white dark:border-red-600';
      case 'medium':
        return 'bg-orange-500 text-white border-orange-500 dark:bg-orange-500 dark:text-white dark:border-orange-500';
      case 'low':
        return 'bg-yellow-500 text-white border-yellow-500 dark:bg-yellow-500 dark:text-white dark:border-yellow-500';
      default:
        return 'bg-gray-500 text-white border-gray-500 dark:bg-gray-500 dark:text-white dark:border-gray-500';
    }
  };

  // Calculate security risk summary
  const calculateRiskSummary = () => {
    try {
      let totalVulns = 0;
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      if (results.open_ports && Array.isArray(results.open_ports)) {
        results.open_ports.forEach(port => {
          if (port.cves && Array.isArray(port.cves)) {
            port.cves.forEach(cve => {
              totalVulns++;
              switch (cve.severity?.toLowerCase()) {
                case 'critical':
                  criticalCount++;
                  break;
                case 'high':
                  highCount++;
                  break;
                case 'medium':
                  mediumCount++;
                  break;
                case 'low':
                  lowCount++;
                  break;
                default:
                  // Unknown severity, count as low
                  lowCount++;
                  break;
              }
            });
          }
        });
      }

      return {
        total: totalVulns,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount
      };
    } catch (error) {
      console.error('Error calculating risk summary:', error);
      return {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      };
    }
  };

  const riskSummary = calculateRiskSummary();


  try {
    return (
      <div className="space-y-6">
        {/* Security Risk Summary Box */}
        <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
          <h2 className="text-xl font-semibold mb-4 text-gray-800 dark:text-gray-200">Security Risk Summary</h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <div className="text-center p-4 bg-gray-50 dark:bg-gray-800/60 rounded-lg">
              <div className="text-3xl font-bold text-gray-800 dark:text-gray-200">{riskSummary.total}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Total Vulnerabilities</div>
            </div>
            <div className="text-center p-4 bg-red-900/10 dark:bg-red-900/20 rounded-lg">
              <div className="text-3xl font-bold text-red-900 dark:text-red-300">{riskSummary.critical}</div>
              <div className="text-sm text-red-700 dark:text-red-400">Critical</div>
            </div>
            <div className="text-center p-4 bg-red-600/10 dark:bg-red-600/20 rounded-lg">
              <div className="text-3xl font-bold text-red-600 dark:text-red-400">{riskSummary.high}</div>
              <div className="text-sm text-red-600 dark:text-red-400">High</div>
            </div>
            <div className="text-center p-4 bg-orange-500/10 dark:bg-orange-500/20 rounded-lg">
              <div className="text-3xl font-bold text-orange-500 dark:text-orange-400">{riskSummary.medium}</div>
              <div className="text-sm text-orange-600 dark:text-orange-400">Medium</div>
            </div>
            <div className="text-center p-4 bg-yellow-500/10 dark:bg-yellow-500/20 rounded-lg">
              <div className="text-3xl font-bold text-yellow-500 dark:text-yellow-400">{riskSummary.low}</div>
              <div className="text-sm text-yellow-600 dark:text-yellow-400">Low</div>
            </div>
          </div>
          {riskSummary.total === 0 && (
            <p className="text-center text-gray-600 dark:text-gray-400 mt-4">
              No known vulnerabilities found for detected services
            </p>
          )}
        </div>

        {/* Port Details */}
        {results.open_ports.map((port, idx) => (
          <div key={idx} className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl border border-gray-100 dark:border-gray-800 card-hover">
            {/* Port Header */}
            <div className="bg-gray-50 dark:bg-gray-800/60 px-6 py-4 border-b border-gray-200 dark:border-gray-700 rounded-t-xl">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <h3 className="text-xl font-bold text-gray-800 dark:text-gray-200">Port {port.port}</h3>
                  <span className="px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border border-green-200 dark:border-green-800">
                    Open
                  </span>
                  {port.service && (
                    <span className="px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
                      {port.service}
                    </span>
                  )}
                </div>
                {port.version && (
                  <div className="text-right">
                    <div className="text-sm text-gray-600 dark:text-gray-400">Version</div>
                    <div className="text-sm font-mono text-gray-800 dark:text-gray-200">{port.version}</div>
                  </div>
                )}
              </div>
              {port.product && (
                <div className="mt-2">
                  <div className="text-sm text-gray-600 dark:text-gray-400">Product: <span className="font-medium text-gray-800 dark:text-gray-200">{port.product}</span></div>
                </div>
              )}
            </div>

            <div className="p-6">
              {/* CVE Information */}
              {port.cves && port.cves.length > 0 ? (
                <div className="mb-6">
                  <h4 className="text-lg font-semibold mb-4 text-gray-800 dark:text-gray-200">
                    Known Vulnerabilities ({port.cves.length})
                  </h4>
                  <div className="space-y-4">
                    {port.cves.map((cve, cveIdx) => (
                      <div key={cveIdx} className="bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <span className="font-mono text-lg font-bold text-gray-800 dark:text-gray-200">
                            {cve.cve_id || cve.id}
                          </span>
                          {cve.severity && (
                            <span className={`px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(cve.severity)}`}>
                              {cve.severity.toUpperCase()}
                            </span>
                          )}
                        </div>
                        
                        {cve.description && (
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">{cve.description}</p>
                        )}
                        
                        <div className="flex flex-wrap items-center gap-4 text-xs">
                          {cve.cvss_score && cve.cvss_score > 0 && (
                            <div className="flex items-center space-x-1">
                              <span className="text-gray-500 dark:text-gray-500">CVSS:</span>
                              <span className="font-medium text-gray-800 dark:text-gray-200">{cve.cvss_score}</span>
                            </div>
                          )}
                          
                          {cve.published_date && (
                            <div className="flex items-center space-x-1">
                              <span className="text-gray-500 dark:text-gray-500">Published:</span>
                              <span className="text-gray-800 dark:text-gray-200">{new Date(cve.published_date).toLocaleDateString()}</span>
                            </div>
                          )}
                          
                          {cve.source && (
                            <div className="flex items-center space-x-1">
                              <span className="text-gray-500 dark:text-gray-500">Source:</span>
                              <span className="text-gray-800 dark:text-gray-200">{cve.source}</span>
                            </div>
                          )}
                        </div>
                        
                        {cve.references && cve.references.length > 0 && (
                          <div className="mt-3">
                            <p className="text-xs text-gray-500 dark:text-gray-500 mb-1">References:</p>
                            <div className="space-y-1">
                              {cve.references.map((ref, refIdx) => (
                                <a 
                                  key={refIdx} 
                                  href={ref} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="text-xs text-blue-600 dark:text-blue-400 hover:underline block truncate"
                                >
                                  {ref}
                                </a>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="mb-6 p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                  <p className="text-green-800 dark:text-green-300 text-center">
                    No known vulnerabilities found for this service
                  </p>
                </div>
              )}

              {/* Security Recommendations */}
              {(port.recommendations || port.service) && (
                <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                  <h4 className="text-lg font-semibold text-blue-800 dark:text-blue-300 mb-3">Security Recommendations</h4>
                  
                  {port.recommendations ? (
                    <div>
                      {port.recommendations.title && (
                        <h5 className="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-2">{port.recommendations.title}</h5>
                      )}
                      {port.recommendations.description && (
                        <p className="text-sm text-blue-700 dark:text-blue-400 mb-3">{port.recommendations.description}</p>
                      )}
                      {port.recommendations.action_items && port.recommendations.action_items.length > 0 && (
                        <ul className="text-sm text-blue-700 dark:text-blue-400 space-y-1">
                          {port.recommendations.action_items.map((item, idx) => (
                            <li key={idx}>• {item}</li>
                          ))}
                        </ul>
                      )}
                      {port.recommendations.alternative_services && port.recommendations.alternative_services.length > 0 && (
                        <div className="mt-3">
                          <p className="text-sm font-medium text-blue-800 dark:text-blue-300 mb-1">Alternative Services:</p>
                          <p className="text-sm text-blue-700 dark:text-blue-400">{port.recommendations.alternative_services.join(', ')}</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <ul className="text-sm text-blue-700 dark:text-blue-400 space-y-1">
                      {port.service?.includes('http') && (
                        <li>• Ensure web server is updated to latest version</li>
                      )}
                      {port.service?.includes('ssh') && (
                        <li>• Use key-based authentication instead of passwords</li>
                      )}
                      {port.service?.includes('ftp') && (
                        <li>• Consider using SFTP or FTPS for secure file transfer</li>
                      )}
                      {port.service?.includes('telnet') && (
                        <li>• Replace with SSH for secure remote access</li>
                      )}
                      <li>• Regularly update and patch all services</li>
                      <li>• Implement proper firewall rules</li>
                    </ul>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}

        {/* Scan Time */}
        {results.scan_time && (
          <div className="text-center text-sm text-gray-500 dark:text-gray-400">
            Scan completed in {results.scan_time} seconds
          </div>
        )}
      </div>
    );
  } catch (error) {
    console.error('Error rendering VersionScanResults:', error);
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-red-800 dark:text-red-300 mb-2">Error Rendering Results</h3>
        <p className="text-red-700 dark:text-red-400">There was an error displaying the scan results. Check the console for details.</p>
        <details className="mt-2">
          <summary className="text-sm text-red-600 dark:text-red-400 cursor-pointer">Error Details</summary>
          <pre className="text-xs text-red-600 dark:text-red-400 mt-2 bg-red-100 dark:bg-red-900/40 p-2 rounded overflow-auto">
            {error.toString()}
          </pre>
        </details>
      </div>
    );
  }
}

export default VersionScanResults;
