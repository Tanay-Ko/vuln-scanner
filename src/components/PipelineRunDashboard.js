import React, { useEffect, useRef, useState } from 'react';
import { runPipeline } from '../api/client';
import PipelineStageCard from './PipelineStageCard';

const STAGES = [
  { id: 'nmap', title: 'Network Ports', tool: 'Nmap', description: 'Checks the authorized target for open ports.' },
  { id: 'zap', title: 'Web Vulnerabilities', tool: 'OWASP ZAP', description: 'Runs a lightweight web baseline assessment.' }
];

const STATUS_LABELS = {
  pending: 'Pending',
  running: 'Running',
  passed: 'Passed',
  completed: 'Completed',
  vulnerabilities_found: 'Vulnerabilities Found',
  failed: 'Failed',
  blocked: 'Blocked',
  skipped: 'Skipped / Idle',
  not_requested: 'Not Run'
};

function PipelineRunDashboard() {
  const [target, setTarget] = useState('');
  const [environmentType, setEnvironmentType] = useState('self_hosted');
  const [nmapEnabled, setNmapEnabled] = useState(false);
  const [pipeline, setPipeline] = useState(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const controller = useRef(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      controller.current?.abort();
    };
  }, []);

  const handleRun = async (event) => {
    event.preventDefault();
    if (!target.trim() || running) return;

    controller.current?.abort();
    controller.current = new AbortController();
    setRunning(true);
    setError('');
    setPipeline(null);
    try {
      const response = await runPipeline(
        target.trim(),
        environmentType,
        nmapEnabled && environmentType === 'self_hosted',
        {
          signal: controller.current.signal
        }
      );
      if (mounted.current) {
        setPipeline(response.pipeline);
        if (response.pipeline.environment_type === 'managed') {
          setEnvironmentType('managed');
        }
      }
    } catch (requestError) {
      if (mounted.current && requestError?.name !== 'AbortError') {
        setError(requestError.message || 'The pipeline could not be completed.');
      }
    } finally {
      if (mounted.current) setRunning(false);
      controller.current = null;
    }
  };

  const stageResults = pipeline?.stages || {};

  return (
    <main className="space-y-6">
      <section className="rounded-2xl border border-gray-200 bg-white/80 p-6 shadow-soft dark:border-gray-800 dark:bg-gray-900/60">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100">
          Continuous Security Pipeline
        </h1>
        <p className="mt-2 text-sm font-semibold uppercase tracking-wide text-blue-600 dark:text-blue-400">
          Authorized live-site assessment
        </p>
        <p className="mt-2 max-w-2xl text-gray-600 dark:text-gray-400">
          This scan checks the live website only. It does not fetch or scan the website's source
          code. Open Source Security for separate repository scans in GitHub Actions.
        </p>

        <form onSubmit={handleRun} className="mt-6 grid gap-4 md:grid-cols-[1fr_auto]">
          <div>
            <label htmlFor="pipeline-target" className="mb-2 block text-sm font-medium">
              Live website target
            </label>
            <input
              id="pipeline-target"
              type="url"
              required
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="http://127.0.0.1:8000"
              disabled={running}
              className="w-full rounded-lg border border-gray-300 bg-white px-4 py-3 text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-gray-700 dark:bg-gray-800 dark:text-white"
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              Network stages run only for targets permitted by the backend target policy.
            </p>
          </div>
          <div>
            <label htmlFor="deployment-type" className="mb-2 block text-sm font-medium">
              Deployment Type
            </label>
            <select
              id="deployment-type"
              value={environmentType}
              onChange={(event) => setEnvironmentType(event.target.value)}
              disabled={running}
              className="w-full rounded-lg border border-gray-300 bg-white px-4 py-3 text-gray-900 focus:border-blue-500 focus:outline-none dark:border-gray-700 dark:bg-gray-800 dark:text-white"
            >
              <option value="managed">Managed Platform (Vercel / Heroku)</option>
              <option value="self_hosted">Self-Hosted VPS</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={running || !target.trim()}
            className="rounded-lg bg-blue-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-gray-400 md:col-span-2"
          >
            {running ? 'Pipeline Running…' : 'Run Security Pipeline'}
          </button>
        </form>
      </section>

      {error && (
        <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
          {error}
        </div>
      )}

      <section
        aria-label="Pipeline stages"
        aria-busy={running}
        className="rounded-2xl border border-gray-200 bg-white/80 p-6 shadow-soft dark:border-gray-800 dark:bg-gray-900/60"
      >
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">Pipeline Run</h2>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              {pipeline
                ? `Run ${pipeline.run_id} · ${pipeline.duration_seconds}s`
                : 'OWASP ZAP checks the website; Nmap is optional for self-hosted infrastructure.'}
            </p>
          </div>
          {pipeline && (
            <span className="rounded-full bg-gray-100 px-3 py-1 text-sm font-semibold capitalize dark:bg-gray-800">
              {STATUS_LABELS[pipeline.status] || pipeline.status.replaceAll('_', ' ')}
            </span>
          )}
        </div>

        <ol className="space-y-4">
          {STAGES.map((stage, index) => {
            const result = stageResults[stage.id] || {};
            const isManagedNmap = stage.id === 'nmap' && environmentType === 'managed';
            const status = result.status
              || (isManagedNmap ? 'skipped' : 'pending');
            const label = STATUS_LABELS[status] || status.replaceAll('_', ' ');
            return (
              <PipelineStageCard
                key={stage.id}
                stage={stage}
                index={index}
                result={result}
                status={status}
                label={label}
                showConnector={index < STAGES.length - 1}
                headerAction={stage.id === 'nmap' ? (
                  <label className="mt-4 flex shrink-0 cursor-pointer items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <span>Nmap</span>
                    <input
                      type="checkbox"
                      role="switch"
                      aria-label="Enable Nmap"
                      checked={nmapEnabled && environmentType === 'self_hosted'}
                      disabled={running || environmentType === 'managed'}
                      onChange={(event) => setNmapEnabled(event.target.checked)}
                      className="peer sr-only"
                    />
                    <span
                      aria-hidden="true"
                      className="relative h-6 w-11 rounded-full bg-gray-300 transition-colors after:absolute after:left-1 after:top-1 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition-transform peer-checked:bg-blue-600 peer-checked:after:translate-x-5 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-blue-600 peer-disabled:cursor-not-allowed peer-disabled:opacity-50 dark:bg-gray-600"
                    />
                    <span className="sr-only">
                      {environmentType === 'managed' ? 'Unavailable for managed platforms' : nmapEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </label>
                ) : null}
              />
            );
          })}
        </ol>
      </section>
    </main>
  );
}

export default PipelineRunDashboard;
