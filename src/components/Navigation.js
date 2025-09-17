import React from 'react';

const Navigation = ({ activeTab, handleTabChange, theme, setTheme }) => {
  return (
    <nav className="bg-white/70 dark:bg-gray-900/50 backdrop-blur-md shadow px-6 py-4 mb-6 border-b border-gray-100 dark:border-gray-800">
      <div className="flex items-center justify-between max-w-6xl mx-auto">
        <h1 className="text-2xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-400">VulnScan</h1>
        <div className="flex items-center gap-4">
          {/* Navigation Tabs */}
          <div className="flex bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
            <button
              onClick={() => handleTabChange('network')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'network' 
                  ? 'bg-white dark:bg-gray-700 text-blue-600 dark:text-blue-400 shadow-sm' 
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
              }`}
            >
              Network Scan
            </button>
            <button
              onClick={() => handleTabChange('web')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'web' 
                  ? 'bg-white dark:bg-gray-700 text-purple-600 dark:text-purple-400 shadow-sm' 
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
              }`}
            >
              Web Scan
            </button>
            <button
              onClick={() => handleTabChange('docs')}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === 'docs' 
                  ? 'bg-white dark:bg-gray-700 text-green-600 dark:text-green-400 shadow-sm' 
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
              }`}
            >
              Documentation
            </button>
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400">v1.0</p>
          <button
            aria-label="Toggle dark mode"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="relative inline-flex h-8 w-14 items-center rounded-full bg-gray-200 dark:bg-gray-700 transition-colors"
          >
            <span className={`inline-block h-6 w-6 transform rounded-full bg-white dark:bg-gray-200 shadow transition-transform ${theme === 'dark' ? 'translate-x-7' : 'translate-x-1'}`}></span>
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
