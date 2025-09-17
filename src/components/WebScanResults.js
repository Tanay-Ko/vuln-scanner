import React from 'react';

function WebScanResults({ results }) {
  if (!results) {
    return null;
  }

  if (results.error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-red-800 dark:text-red-300 mb-2">Scan Error</h3>
        <p className="text-red-700 dark:text-red-400">{results.error}</p>
      </div>
    );
  }

  if (results.web_scan) {
    const webScan = results.web_scan;
    
    if (webScan.error) {
      return (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-red-800 dark:text-red-300 mb-2">ZAP Scan Error</h3>
          <p className="text-red-700 dark:text-red-400">{webScan.error}</p>
        </div>
      );
    }

    const findings = webScan.findings || [];
    
    return (
      <div className="space-y-4">
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-blue-800 dark:text-blue-300 mb-2">Scan Summary</h3>
          <p className="text-blue-700 dark:text-blue-400">
            <strong>Target:</strong> {webScan.target_url || results.target}
          </p>
          <p className="text-blue-700 dark:text-blue-400">
            <strong>Security Issues Found:</strong> {findings.length}
          </p>
        </div>

        {findings.length > 0 ? (
          <div className="space-y-3">
            <h3 className="text-lg font-semibold">Security Findings</h3>
            {findings.map((finding, idx) => (
              <div key={idx} className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-semibold text-yellow-800 dark:text-yellow-300">
                    {finding.name}
                  </h4>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    finding.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300' :
                    finding.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' :
                    finding.severity === 'low' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' :
                    'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300'
                  }`}>
                    {finding.severity}
                  </span>
                </div>
                
                <p className="text-yellow-700 dark:text-yellow-400 mb-2">
                  {finding.description}
                </p>
                
                <div className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                  <p><strong>URL:</strong> {finding.url}</p>
                  <p><strong>Confidence:</strong> {finding.confidence}</p>
                  {finding.solution && (
                    <div>
                      <strong>Solution:</strong>
                      <p className="mt-1 text-gray-700 dark:text-gray-300">{finding.solution}</p>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-green-800 dark:text-green-300 mb-2">No Security Issues Found</h3>
            <p className="text-green-700 dark:text-green-400">
              The web scan completed successfully and no security vulnerabilities were detected.
            </p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <p className="text-gray-600 dark:text-gray-400">No web scan data available.</p>
    </div>
  );
}

export default WebScanResults;
