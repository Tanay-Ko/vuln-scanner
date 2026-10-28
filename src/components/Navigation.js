import React from 'react';

const Navigation = ({ currentView, setCurrentView, theme, setTheme }) => {
  const links = [
    { id: 'pipeline', label: 'Live-site Scan' },
    { id: 'source-security', label: 'Source Security' },
    { id: 'documentation', label: 'Documentation' }
  ];

  return (
    <nav className="bg-white/70 dark:bg-gray-900/50 backdrop-blur-md shadow px-6 py-4 mb-6 border-b border-gray-100 dark:border-gray-800">
      <div className="flex flex-wrap items-center justify-between gap-4 max-w-6xl mx-auto">
        <h1 className="text-2xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-400">VulnScan</h1>
        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          {links.map((link) => (
            <button
              key={link.id}
              type="button"
              aria-current={currentView === link.id ? 'page' : undefined}
              onClick={() => setCurrentView(link.id)}
              className={`rounded-lg px-3 py-2 text-sm font-medium ${
                currentView === link.id
                  ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200'
                  : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800'
              }`}
            >
              {link.label}
            </button>
          ))}
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
