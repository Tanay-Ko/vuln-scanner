import React from 'react';

const SEVERITY_STYLES = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200',
  high: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200',
  medium: 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200',
  low: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
  info: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  safe: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  unknown: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200'
};

const STATUS_STYLES = {
  passed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  completed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  vulnerabilities_found: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-200',
  failed: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200',
  blocked: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200',
  skipped: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200',
  running: 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200',
  pending: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-300'
};

function getSeverity(value) {
  const normalized = String(value || 'info').toLowerCase();
  if (normalized.includes('critical')) return 'Critical';
  if (normalized.includes('high')) return 'High';
  if (normalized.includes('medium')) return 'Medium';
  if (normalized.includes('low')) return 'Low';
  if (normalized.includes('info')) return 'Info';
  if (normalized.includes('safe')) return 'Safe';
  return 'Info';
}

function getSeverityClass(severity) {
  const key = severity.toLowerCase();
  return SEVERITY_STYLES[key] || SEVERITY_STYLES.unknown;
}

function getFindings(stageId, stage) {
  const nativeFindings = stage?.findings;

  if (stageId === 'gitleaks' && Array.isArray(nativeFindings)) {
    return nativeFindings.map((finding) => ({
      issue: finding.Description || finding.description || finding.RuleID || 'Potential secret detected',
      where: [finding.File, finding.Line ? `line ${finding.Line}` : null].filter(Boolean).join(':'),
      remediation: 'Rotate the credential, remove it from the source, and clean it from repository history.',
      severity: getSeverity(finding.Severity || 'high'),
      secret: true
    }));
  }

  if (stageId === 'trivy' && Array.isArray(nativeFindings?.Results)) {
    return nativeFindings.Results.flatMap((result) =>
      (Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : []).map((vulnerability) => {
        const fixedVersion = vulnerability.FixedVersion;
        return {
          issue: vulnerability.VulnerabilityID || vulnerability.Title || 'Dependency vulnerability',
          where: [vulnerability.PkgName, result.Target].filter(Boolean).join(' · '),
          remediation: fixedVersion
            ? `Upgrade to version ${fixedVersion}.`
            : 'Upgrade the package to a patched version or replace it with a maintained alternative.',
          severity: getSeverity(vulnerability.Severity),
          note: vulnerability.Title || vulnerability.Description || ''
        };
      })
    );
  }

  if (stageId === 'nmap') {
    const ports = Array.isArray(nativeFindings?.open_ports) ? nativeFindings.open_ports : [];
    return ports.map((port) => ({
      issue: `Open port ${port.port}${port.service ? ` (${port.service})` : ''}`,
      where: [stage?.target, port.port ? `port ${port.port}` : null].filter(Boolean).join(' · '),
      remediation: 'Confirm this service needs to be reachable; close or firewall the port if it is not required.',
      severity: 'Info',
      note: [port.product, port.version].filter(Boolean).join(' ')
    }));
  }

  if (stageId === 'zap' && Array.isArray(nativeFindings)) {
    return nativeFindings.map((finding) => ({
      issue: finding.name || finding.description || 'Web application alert',
      where: finding.url || stage?.target || 'Target URL unavailable',
      remediation: finding.solution || 'Review the alert details and apply the recommended secure configuration.',
      severity: getSeverity(finding.severity),
      note: finding.description || ''
    }));
  }

  return [];
}

function getStageMessage(stageId, status, findings, result) {
  if (status === 'skipped' && stageId === 'nmap') {
    return result.reason || 'Bypassed / Idle (Managed Platform). Network port scanning is not run for managed deployments.';
  }
  if (status === 'failed' || status === 'blocked') {
    return result.error || result.reason || 'This stage did not complete.';
  }
  if (findings.length > 0) {
    if (stageId === 'nmap') return `${findings.length} open port${findings.length === 1 ? '' : 's'} discovered.`;
    return `${findings.length} finding${findings.length === 1 ? '' : 's'} reported.`;
  }
  if (status === 'passed' || status === 'completed') {
    return stageId === 'nmap' ? 'No open ports found.' : 'No Vulnerabilities Found';
  }
  return result.reason || '';
}

function PipelineStageCard({
  stage,
  index,
  result,
  status,
  label,
  showConnector = index < 3,
  headerAction
}) {
  const findings = getFindings(stage.id, result);
  const message = getStageMessage(stage.id, status, findings, result);
  const emptySuccess = findings.length === 0 && (status === 'passed' || status === 'completed');
  const skipped = status === 'skipped';

  return (
    <li className="relative">
      {showConnector && (
        <span
          aria-hidden="true"
          className="absolute left-5 top-12 h-[calc(100%+1rem)] w-px bg-gray-200 dark:bg-gray-700"
        />
      )}
      <div className="flex min-w-0 items-start gap-3">
        <details
          open={findings.length > 0 || status === 'failed' || status === 'blocked'}
          className="group relative min-w-0 flex-1 rounded-xl border border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800/70"
        >
          <summary className="flex min-w-0 cursor-pointer list-none items-start gap-4 p-4 [&::-webkit-details-marker]:hidden">
            <span className={`z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-sm font-bold ${
              emptySuccess
                ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
                : status === 'vulnerabilities_found' || status === 'failed'
                  ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300'
                  : status === 'running'
                    ? 'animate-pulse bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                    : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'
            }`}>
              {String(index + 1).padStart(2, '0')}
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="min-w-0">
                  <h3 className="font-semibold text-gray-900 dark:text-gray-100">{stage.title}</h3>
                  <span className="block break-words text-sm text-gray-500 dark:text-gray-400 [overflow-wrap:anywhere]">
                    {stage.tool} · {stage.description}
                  </span>
                </span>
                <span className={`shrink-0 rounded-full px-3 py-1 text-xs font-semibold ${STATUS_STYLES[status] || STATUS_STYLES.pending}`}>
                  {label}
                </span>
              </span>
              {message && (
                <span className={`mt-3 block break-words text-sm [overflow-wrap:anywhere] ${
                  skipped ? 'text-gray-600 dark:text-gray-300'
                    : emptySuccess ? 'font-medium text-emerald-700 dark:text-emerald-300'
                      : status === 'failed' || status === 'blocked' ? 'text-rose-700 dark:text-rose-300'
                        : 'text-gray-700 dark:text-gray-300'
                }`}>
                  {emptySuccess && <span aria-hidden="true" className="mr-2">✓</span>}
                  {message}
                </span>
              )}
            </span>
            <span aria-hidden="true" className="mt-1 text-gray-400 transition-transform group-open:rotate-180">⌄</span>
          </summary>

          <div className="min-w-0 space-y-3 border-t border-gray-100 px-4 pb-4 pt-4 dark:border-gray-700 sm:pl-[4.5rem]">
            {findings.length > 0 ? findings.map((finding, findingIndex) => (
              <article
                key={`${stage.id}-${finding.issue}-${findingIndex}`}
                className="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900/60"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Issue</p>
                    <h4 className="mt-1 break-words font-semibold text-gray-900 dark:text-gray-100 [overflow-wrap:anywhere]">{finding.issue}</h4>
                  </div>
                  <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${getSeverityClass(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
                {finding.note && (
                  <p className="mt-2 break-words whitespace-normal text-sm text-gray-600 dark:text-gray-300 [overflow-wrap:anywhere]">{finding.note}</p>
                )}
                {finding.secret && (
                  <p className="mt-2 text-sm font-medium text-emerald-700 dark:text-emerald-300">
                    Secret value hidden for safety. Rotate the credential if it is real.
                  </p>
                )}
                <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="font-medium text-gray-500 dark:text-gray-400">Where</dt>
                    <dd className="mt-1 break-words text-gray-800 dark:text-gray-200 [overflow-wrap:anywhere]">{finding.where || 'Location unavailable'}</dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="font-medium text-gray-500 dark:text-gray-400">Remediation</dt>
                    <dd className="mt-1 break-words text-gray-800 dark:text-gray-200 [overflow-wrap:anywhere]">{finding.remediation}</dd>
                  </div>
                </dl>
              </article>
            )) : status === 'failed' || status === 'blocked' ? (
              <p className="rounded-lg bg-rose-50 p-3 text-sm text-rose-800 dark:bg-rose-950/50 dark:text-rose-200">
                {result.error || result.reason || 'This stage did not complete.'}
              </p>
            ) : skipped ? (
              <p className="rounded-lg bg-gray-100 p-3 text-sm text-gray-700 dark:bg-gray-800 dark:text-gray-200">
                {result.reason || 'Bypassed / Idle (Managed Platform)'}
              </p>
            ) : emptySuccess ? (
              <p className="rounded-lg bg-emerald-50 p-3 text-sm font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200">
                ✓ No Vulnerabilities Found
              </p>
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400">No findings to display yet.</p>
            )}
            {result.report_path && (
              <p className="break-words pt-1 text-xs text-gray-500 dark:text-gray-400 [overflow-wrap:anywhere]">
                JSON report: {result.report_path}
              </p>
            )}
          </div>
        </details>
        {headerAction}
      </div>
    </li>
  );
}

export default PipelineStageCard;
