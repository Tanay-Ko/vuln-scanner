import './App.css';
import './index.css'; 
import React, { useEffect, useState } from 'react';
import Navigation from './components/Navigation';
import Documentation from './components/Documentation';
import NetworkScanForm from './components/NetworkScanForm';
import WebScanForm from './components/WebScanForm';

function App() {
  const [theme, setTheme] = useState(document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  const [activeTab, setActiveTab] = useState('network'); // 'network', 'web', or 'docs'

  const handleTabChange = (newTab) => {
    setActiveTab(newTab);
  };

  // Theme management
  useEffect(() => {
    try {
      document.documentElement.classList.toggle('dark', theme === 'dark');
      localStorage.setItem('theme', theme);
    } catch (e) {}
  }, [theme]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-indigo-50 text-gray-800 dark:from-gray-950 dark:to-gray-900 dark:text-gray-100 theme-transition">
      {/* Decorative background */}
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10">
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-gradient-to-br from-blue-400/20 to-indigo-400/10 blur-3xl"></div>
        <div className="absolute bottom-0 right-0 h-80 w-80 rounded-full bg-gradient-to-tr from-purple-400/10 to-pink-400/10 blur-3xl"></div>
      </div>

      <Navigation 
        activeTab={activeTab}
        handleTabChange={handleTabChange}
        theme={theme}
        setTheme={setTheme}
      />

      {/* Main Container */}
      <div className="relative max-w-4xl mx-auto px-4 animate-fadeIn">
        {activeTab === 'docs' ? (
          <Documentation />
        ) : activeTab === 'network' ? (
          <NetworkScanForm />
        ) : activeTab === 'web' ? (
          <WebScanForm />
        ) : null}
      </div>
    </div>
  );
}

export default App;