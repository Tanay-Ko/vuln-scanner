import './App.css';
import './index.css'; 
import React, { useEffect, useRef, useState } from 'react';
import Navigation from './components/Navigation';
import ScanForm from './components/ScanForm';
import ProgressBar from './components/ProgressBar';
import Documentation from './components/Documentation';
import NetworkScanForm from './components/NetworkScanForm';

function App() {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('basic');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [theme, setTheme] = useState(document.documentElement.classList.contains('dark') ? 'dark' : 'light');
  const [progress, setProgress] = useState(0);
  const [activeTab, setActiveTab] = useState('network'); // 'network', 'web', or 'docs'
  const [webScanTimeLimit, setWebScanTimeLimit] = useState(120); // Default 2 minutes
  const [useTimeLimit, setUseTimeLimit] = useState(true);
  const progressTimer = useRef(null);
  const scanAbortController = useRef(null);
  const isMounted = useRef(true);


  const handleScan = async () => {
    console.log('handleScan called with target:', target);
    if (!target) {
      console.log('No target, returning early');
      return;
    }

    console.log('Starting scan...');
    setLoading(true);
    setResults(null);
    setError(null);
    setProgress(0);

    // Simulate progress while waiting for backend response
    if (progressTimer.current) clearInterval(progressTimer.current);
    const isVersion = scanType === 'version detection';
    const isWebScan = activeTab === 'web';
    let tickMs, increment;
    
    if (isVersion) {
      tickMs = 900; // ~81s to 90% for version detection
      increment = 1;
    } else if (isWebScan) {
      // Adjust progress speed based on time limit
      const timeLimit = useTimeLimit ? webScanTimeLimit : 300; // Default 5 min if no limit
      tickMs = Math.max(200, timeLimit * 10); // Scale progress to time limit
      increment = 1;
    } else {
      tickMs = 300; // fast for basic
      increment = Math.floor(Math.random() * 3) + 1;
    }
    
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
      if (activeTab === 'web') {
        requestBody.scanType = 'web scan';
        if (useTimeLimit && webScanTimeLimit && !isNaN(webScanTimeLimit) && webScanTimeLimit >= 30) {
          requestBody.timeLimit = webScanTimeLimit;
        }
      }

      const response = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal
      });

      console.log('Response status:', response.status);
      console.log('Response ok:', response.ok);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', errorText);
        throw new Error(`API Error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('API Response data:', data);
      if (isMounted.current) {
        console.log('Setting results:', data);
      setResults(data);
      }
    } catch (err) {
      if (isMounted.current) {
        if (err && err.name === 'AbortError') {
          // aborted; do nothing
        } else {
      setResults({ error: 'Failed to scan. Make sure the backend is running.' });
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

  const handleScanTypeChange = (e) => {
    const newScanType = e.target.value;
    setScanType(newScanType);
    
    // Clear results when switching from basic to version detection
    if (scanType === 'basic' && newScanType === 'version detection') {
      setResults(null);
    }
  };

  const handleTabChange = (newTab) => {
    // Clear results when switching between network and web tabs
    if ((activeTab === 'network' && newTab === 'web') || 
        (activeTab === 'web' && newTab === 'network')) {
      setResults(null);
    }
    setActiveTab(newTab);
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isMounted.current = false;
      if (progressTimer.current) clearInterval(progressTimer.current);
      if (scanAbortController.current) {
        try { scanAbortController.current.abort(); } catch (_) {}
      }
    };
  }, []);

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
        ) : (
          <>
            <ScanForm
              target={target}
              setTarget={setTarget}
              scanType={scanType}
              handleScanTypeChange={handleScanTypeChange}
              handleScan={handleScan}
              loading={loading}
              activeTab={activeTab}
              webScanTimeLimit={webScanTimeLimit}
              setWebScanTimeLimit={setWebScanTimeLimit}
              useTimeLimit={useTimeLimit}
              setUseTimeLimit={setUseTimeLimit}
            />

            <ProgressBar 
              loading={loading}
              progress={progress}
              activeTab={activeTab}
            />
          </>
        )}
      </div>
    </div>
  );
}

export default App;