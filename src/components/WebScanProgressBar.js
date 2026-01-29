import React from 'react';

const WebScanProgressBar = ({ loading, progress, activeTab }) => {
  if (!loading && progress === 0) return null;

  return (
    <div className="mb-6">
      <div className="h-2 w-full rounded-full bg-gray-200 dark:bg-gray-800 overflow-hidden">
        <div
          className={`h-full rounded-full transition-[width] duration-500 ${
            activeTab === 'web' 
              ? 'bg-gradient-to-r from-purple-500 via-pink-500 to-red-500'
              : 'bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500'
          }`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="mt-2 flex justify-end">
        <span className="text-xs text-gray-600 dark:text-gray-400">{Math.floor(progress)}%</span>
      </div>
    </div>
  );
};

export default WebScanProgressBar;
