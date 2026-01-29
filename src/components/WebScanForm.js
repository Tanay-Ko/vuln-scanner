import React, { useState, useRef } from 'react';
import WebScanProgressBar from './WebScanProgressBar';

function WebScanForm() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  
  
  const scanAbortController = useRef(null);
  const progressTimer = useRef(null);
  const isMounted = useRef(true);

  const handleScan = async () => {
    if (!target.trim()) {
      alert('Please enter a target URL');
      return;
    }

    setLoading(true);
    setResults(null);
    setProgress(0);

    // Start progress simulation - slower for web scans (reach 90% in ~60 seconds)
    const tickMs = 1000;
    progressTimer.current = setInterval(() => {
      setProgress((prev) => {
        const next = prev + Math.random() * 1.5;
        return next >= 90 ? 90 : next;
      });
    }, tickMs);

    try {
      if (scanAbortController.current) {
        try { scanAbortController.current.abort(); } catch (_) {}
      }
      scanAbortController.current = new AbortController();
      const { signal } = scanAbortController.current;
      
      const requestBody = { 
        target, 
        scanType: 'web scan'
      };

      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal,
        // Add a reasonable timeout
        timeout: 60000  // 60 seconds max
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API Error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      if (err && err.name === 'AbortError') {
        // aborted; do nothing
      } else {
        setResults({ error: 'Failed to scan. Make sure the backend is running and ZAP is started.' });
      }
    } finally {
      // Complete and clean up progress
      if (progressTimer.current) clearInterval(progressTimer.current);
      setProgress(100);
      setLoading(false);
      setTimeout(() => {
        setProgress(0);
      }, 500);
      scanAbortController.current = null;
    }
  };

  const handleCancel = () => {
    if (scanAbortController.current) {
      scanAbortController.current.abort();
    }
    setLoading(false);
    setProgress(0);
    if (progressTimer.current) clearInterval(progressTimer.current);
  };

  React.useEffect(() => {
    return () => {
      isMounted.current = false;
      if (scanAbortController.current) {
        scanAbortController.current.abort();
      }
      if (progressTimer.current) clearInterval(progressTimer.current);
    };
  }, []);

  return (
    <div className="space-y-6">
      {/* Web Scan Form */}
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Web Security Scan</h2>
        
        <div className="space-y-4">
          <div>
            <label htmlFor="web-target" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Target URL
            </label>
            <input
              id="web-target"
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              disabled={loading}
            />
          </div>


          <div className="flex space-x-3">
            <button
              onClick={handleScan}
              disabled={loading || !target.trim()}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition-colors duration-200 flex items-center space-x-2"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <span>Start Web Scan</span>
                </>
              )}
            </button>
            
            {loading && (
              <button
                onClick={handleCancel}
                className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors duration-200"
              >
                Cancel
              </button>
            )}
          </div>

          {loading && <WebScanProgressBar progress={progress} />}
        </div>
      </div>

      {/* Results Container */}
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Web Scan Results</h2>
        
        
        {results ? (
          <WebScanResults results={results} />
        ) : (
          <div className="text-center py-8">
            <div className="text-gray-400 dark:text-gray-500 mb-2">
              <svg className="w-12 h-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-gray-500 dark:text-gray-400">
              {loading ? 'Scanning in progress...' : 'No scan results yet. Enter a target URL and click Start Web Scan to begin.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// WebScanResults component
function WebScanResults({ results }) {
  console.log('WebScanResults: Received results:', results);
  if (!results) {
    console.log('WebScanResults: No results, returning null');
    return null;
  }

  // Handle error results
  if (results.error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-red-800 dark:text-red-300 mb-2">Scan Error</h3>
        <p className="text-red-700 dark:text-red-400">{results.error}</p>
      </div>
    );
  }

  // Handle web scan results
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
                  <h4 className="font-semibold text-yellow-800 dark:text-yellow-300">{finding.name}</h4>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    finding.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                    finding.severity === 'medium' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200' :
                    finding.severity === 'low' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' :
                    'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
                  }`}>
                    {finding.severity?.toUpperCase() || 'INFO'}
                  </span>
                </div>
                
                {finding.description && (
                  <p className="text-yellow-700 dark:text-yellow-400 mb-2 text-sm">{finding.description}</p>
                )}
                
                {finding.url && (
                  <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
                    <strong>URL:</strong> {finding.url}
                  </p>
                )}
                
                {finding.solution && (
                  <div className="mt-2 p-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded">
                    <p className="text-xs font-medium text-green-800 dark:text-green-300 mb-1">Solution:</p>
                    <p className="text-xs text-green-700 dark:text-green-400">{finding.solution}</p>
                  </div>
                )}
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

export default WebScanForm;
