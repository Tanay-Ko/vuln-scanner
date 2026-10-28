import React from 'react';

const WORKFLOW_URL = 'https://github.com/Tanay-Ko/vuln-scanner/actions/workflows/source-security.yml';

function SourceSecurityDashboard() {
  return (
    <main className="space-y-6">
      <section className="rounded-2xl border border-gray-200 bg-white/80 p-6 shadow-soft dark:border-gray-800 dark:bg-gray-900/60">
        <p className="text-sm font-semibold uppercase tracking-wide text-blue-600 dark:text-blue-400">
          GitHub Actions · Repository source
        </p>
        <h1 className="mt-2 text-3xl font-bold text-gray-900 dark:text-gray-100">
          Source Security
        </h1>
        <p className="mt-3 max-w-2xl text-gray-600 dark:text-gray-400">
          These checks run in GitHub Actions against this repository's checked-out code. They are
          separate from live website scans and do not receive source files from a website URL.
        </p>
      </section>

      <section className="grid gap-4 md:grid-cols-2" aria-label="Source security tools">
        <article className="rounded-2xl border border-gray-200 bg-white/80 p-6 shadow-soft dark:border-gray-800 dark:bg-gray-900/60">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Gitleaks</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Checks repository files and Git history for accidentally committed secrets. Secret
            matches are redacted in workflow output.
          </p>
        </article>
        <article className="rounded-2xl border border-gray-200 bg-white/80 p-6 shadow-soft dark:border-gray-800 dark:bg-gray-900/60">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">Trivy</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Checks dependency manifests and lockfiles in this repository for known vulnerabilities.
          </p>
        </article>
      </section>

      <section className="rounded-2xl border border-blue-200 bg-blue-50/80 p-6 dark:border-blue-900 dark:bg-blue-950/30">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          View workflow results
        </h2>
        <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">
          Review findings in GitHub Actions. This dashboard does not store or display source scan
          reports.
        </p>
        <a
          href={WORKFLOW_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4 inline-flex rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white transition-colors hover:bg-blue-700"
        >
          Open GitHub Actions
        </a>
      </section>
    </main>
  );
}

export default SourceSecurityDashboard;
