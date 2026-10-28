import React from 'react';

const Documentation = () => {
  return (
    <div className="space-y-6">
      <div className="bg-white/80 dark:bg-gray-900/60 backdrop-blur-md shadow-soft rounded-xl p-6 border border-gray-100 dark:border-gray-800">
        <h1 className="text-3xl font-bold mb-6 text-gray-900 dark:text-gray-100">VulnScan Documentation</h1>
        <p className="text-lg text-gray-600 dark:text-gray-400 mb-8">
          Source security and live-site assessments are separate workflows in VulnScan.
        </p>
        <ol className="list-inside list-decimal space-y-3 text-gray-700 dark:text-gray-300">
          <li>Gitleaks scans the checked-out repository and Git history in GitHub Actions.</li>
          <li>Trivy scans dependency files in the checked-out repository in GitHub Actions.</li>
          <li>OWASP ZAP checks the approved website. Nmap is optional and is for self-hosted infrastructure you control, such as a VPS.</li>
        </ol>
        <p className="mt-6 text-sm text-gray-600 dark:text-gray-400">
          The website URL does not provide source code. Gitleaks and Trivy run in the repository's
          GitHub Actions workflow; open Source Security to access its results in repository Actions.
          Nmap and ZAP targets are restricted by the backend <code>SCAN_ALLOWED_TARGETS</code>
          setting.
        </p>
        <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">
          Enable Nmap when you want to check exposed ports and services on a dedicated host you own
          or are authorized to assess. It is usually not useful for Vercel/Heroku-hosted apps, where
          scans may see shared hosting infrastructure or filtered ports instead of your app server.
          Managed deployments skip Nmap; OWASP ZAP remains the live HTTP application check.
        </p>
      </div>
    </div>
  );
};

export default Documentation;
