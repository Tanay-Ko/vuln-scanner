import React from 'react';

const ScanForm = ({ 
  target, 
  setTarget, 
  scanType, 
  handleScanTypeChange, 
  handleScan, 
  loading, 
  activeTab,
  webScanTimeLimit,
  setWebScanTimeLimit,
  useTimeLimit,
  setUseTimeLimit
}) => {
  if (activeTab === 'network') {
    return (
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 mb-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Network Security Scan</h2>
        <div className="flex flex-col sm:flex-row gap-4">
          <input
            type="text"
            placeholder="Enter IP or domain (e.g. scanme.nmap.org)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          />
          <select
            value={scanType}
            onChange={handleScanTypeChange}
            className="border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
          >
            <option value="basic">Basic</option>
            <option value="version detection">Version Detection</option>
          </select>
          <button
            onClick={handleScan}
            className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-5 py-2 rounded-lg shadow focus:outline-none focus:ring-2 focus:ring-purple-500/50 active:scale-[0.98] transition"
            disabled={loading}
          >
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>
    );
  }

  if (activeTab === 'web') {
    return (
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 mb-6 border border-gray-100 dark:border-gray-800 card-hover">
        <h2 className="text-xl font-semibold mb-4">Web Application Security Scan</h2>
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-4">
            <input
              type="text"
              placeholder="Enter URL (e.g. https://example.com or http://testphp.vulnweb.com)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="flex-1 border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
            />
            <button
              onClick={handleScan}
              className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-5 py-2 rounded-lg shadow focus:outline-none focus:ring-2 focus:ring-purple-500/50 active:scale-[0.98] transition"
              disabled={loading}
            >
              {loading ? 'Scanning...' : 'Scan'}
            </button>
          </div>

          {/* Time Limit Options */}
          <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
            <h3 className="text-sm font-semibold mb-3 text-gray-700 dark:text-gray-300">Scan Time Limit</h3>
            <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={useTimeLimit}
                  onChange={(e) => setUseTimeLimit(e.target.checked)}
                  className="mr-2 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Set time limit</span>
              </label>
              
              {useTimeLimit && (
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="30"
                    max="1800"
                    value={webScanTimeLimit}
                    onChange={(e) => {
                      const value = e.target.value;
                      if (value === '') {
                        setWebScanTimeLimit('');
                      } else {
                        const numValue = parseInt(value);
                        if (!isNaN(numValue)) {
                          setWebScanTimeLimit(numValue);
                        }
                      }
                    }}
                    className={`w-20 border rounded px-3 py-1 text-sm focus:outline-none focus:ring-2 ${
                      webScanTimeLimit && (webScanTimeLimit < 30 || webScanTimeLimit > 1800)
                        ? 'border-red-300 bg-red-50 dark:border-red-700 dark:bg-red-900/20 focus:ring-red-500/50'
                        : 'border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 focus:ring-purple-500/50'
                    }`}
                  />
                  <span className="text-sm text-gray-600 dark:text-gray-400">seconds</span>
                  {webScanTimeLimit && (webScanTimeLimit < 30 || webScanTimeLimit > 1800) && (
                    <span className="text-xs text-red-600 dark:text-red-400">
                      Must be 30-1800 seconds
                    </span>
                  )}
                </div>
              )}
              
              {!useTimeLimit && (
                <span className="text-sm text-orange-600 dark:text-orange-400 font-medium">
                  ⚠️ No time limit - scan may take a very long time
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
              Recommended: 60-300 seconds for most websites. Longer scans find more vulnerabilities but take more time.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return null;
};

export default ScanForm;
