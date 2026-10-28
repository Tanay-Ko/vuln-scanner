import './App.css';
import './index.css'; 
import React, { useEffect, useState } from 'react';
import Navigation from './components/Navigation';
import Documentation from './components/Documentation';
import PipelineRunDashboard from './components/PipelineRunDashboard';
import SourceSecurityDashboard from './components/SourceSecurityDashboard';

function App() {
  const [theme, setTheme] = useState(document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  const [currentView, setCurrentView] = useState('pipeline');

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
        currentView={currentView}
        setCurrentView={setCurrentView}
        theme={theme}
        setTheme={setTheme}
      />

      <div className="relative max-w-4xl mx-auto px-4 animate-fadeIn">
        {currentView === 'source-security' ? <SourceSecurityDashboard />
          : currentView === 'documentation' ? <Documentation />
            : <PipelineRunDashboard />}
      </div>
    </div>
  );
}

export default App;