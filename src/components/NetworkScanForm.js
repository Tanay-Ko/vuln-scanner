import React, { useState, useRef, useEffect } from 'react';
import BasicScanResults from './BasicScanResults';
import VersionScanResults from './VersionScanResults';

function NetworkScanForm() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [previousScanType, setPreviousScanType] = useState('basic');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [progress, setProgress] = useState(0);
  const progressTimer = useRef(null);
  const scanAbortController = useRef(null);
  const isMounted = useRef(true);

  useEffect(() => {
    return () => {
      isMounted.current = false;
      if (progressTimer.current) clearInterval(progressTimer.current);
      if (scanAbortController.current) {
        try { scanAbortController.current.abort(); } catch (_) {}
      }
    };
  }, []);

  const handleScanTypeChange = (newScanType) => {
    // Reset target and results only when switching from basic to version
    if (previousScanType === 'basic' && newScanType === 'version detection') {
      setTarget('');
      setResults(null);
    }
    // Keep target when switching from version to basic
    setScanType(newScanType);
    setPreviousScanType(newScanType);
  };

  const handleScan = async () => {
    if (!target) {
      return;
    }
    setLoading(true);
    setResults(null);
    setProgress(0);

    // Simulate progress while waiting for backend response
    if (progressTimer.current) clearInterval(progressTimer.current);
    const isVersion = scanType === 'version detection';
    const tickMs = isVersion ? 200 : 100;
    const increment = isVersion ? 2 : 4;

    progressTimer.current = setInterval(() => {
      setProgress((prev) => {
        const next = prev + increment;
        return next >= 90 ? 90 : next;
      });
    }, tickMs);

    try {
      if (scanAbortController.current) {
        try { scanAbortController.current.abort(); } catch (_) {}
      }
      scanAbortController.current = new AbortController();
      const { signal } = scanAbortController.current;
      const requestBody = { target, scanType };

      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', errorText);
        throw new Error(`API Error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      if (isMounted.current) {
        if (err && err.name === 'AbortError') {
          // aborted; do nothing
        }
      }
    } finally {
      // Complete and clean up progress
      if (progressTimer.current) clearInterval(progressTimer.current);
      setProgress(100);
      setLoading(false); // Clear loading state immediately
      setTimeout(() => {
        if (isMounted.current) setProgress(0);
      }, 500); // Keep progress bar visible for a moment
      scanAbortController.current = null;
    }
  };

  const handleStop = () => {
    if (scanAbortController.current) {
      try { scanAbortController.current.abort(); } catch (_) {}
    }
    setLoading(false);
    setProgress(0);
    if (progressTimer.current) clearInterval(progressTimer.current);
  };

  return (
    <div className="space-y-6">
      {/* Scan Form */}
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Network Scan</h2>
        
        <div className="space-y-4">
          <div>
            <label htmlFor="target" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Target
            </label>
            <input
              type="text"
              id="target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter IP address or hostname (e.g., scanme.nmap.org)"
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              disabled={loading}
            />
          </div>

          <div>
            <label htmlFor="scanType" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Scan Type
            </label>
            <select
              id="scanType"
              value={scanType}
              onChange={(e) => handleScanTypeChange(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              disabled={loading}
            >
              <option value="basic">Basic Scan (Fast)</option>
              <option value="version detection">Version Detection (Slower)</option>
            </select>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={handleScan}
              disabled={loading || !target.trim()}
              className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200"
            >
              {loading ? 'Scanning...' : 'Start Scan'}
            </button>
            
            {loading && (
              <button
                onClick={handleStop}
                className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200"
              >
                Stop
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      {loading && (
        <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Scanning in progress...
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {progress}%
            </span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div
              className="bg-blue-600 h-2 rounded-full transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}


      {/* Results Container - Always Visible */}
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Network Scan Results</h2>
        
        {results ? (
          <>
            {scanType === 'basic' ? (
              <BasicScanResults results={results} />
            ) : (
              <VersionScanResults results={results} />
            )}
          </>
        ) : (
          <div className="text-center py-8">
            <div className="text-gray-400 dark:text-gray-500 mb-2">
              <svg className="w-12 h-12 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="text-gray-500 dark:text-gray-400">
              {loading ? 'Scanning in progress...' : 'No scan results yet. Enter a target and click Scan to begin.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default NetworkScanForm;
