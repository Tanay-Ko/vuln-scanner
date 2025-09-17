import React from 'react';

function BasicScanResults({ results }) {
  if (!results || !results.open_ports) return null;

  return (
    <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800 card-hover">
      <h2 className="text-xl font-semibold mb-4">Basic Scan Results</h2>
      
      <p className="mb-2">
        <strong>Target:</strong> {results.target}
      </p>
      
      <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-800/60 rounded-lg border border-gray-100 dark:border-gray-800">
        <h3 className="text-lg font-semibold mb-4">Open Ports ({results.open_ports.length} found)</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {results.open_ports.map((port, idx) => (
            <div key={idx} className="bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-400/80 p-4 rounded-lg shadow-sm">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <h4 className="font-bold text-blue-700 dark:text-blue-300">Port {port.port}</h4>
                    <span className="px-2 py-1 rounded text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                      Open
                    </span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 mb-2">
                    <span className="font-medium">Service:</span> {port.service}
                  </p>
                  {port.version && (
                    <div className="mt-2">
                      <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Version:</p>
                      <div className="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-400/80 p-2 rounded">
                        <span className="text-sm font-mono">{port.version}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {results.scan_time && (
        <p className="text-sm text-gray-400 dark:text-gray-500 mt-3">
          Scan time: {results.scan_time} seconds
        </p>
      )}
    </div>
  );
}

export default BasicScanResults;
