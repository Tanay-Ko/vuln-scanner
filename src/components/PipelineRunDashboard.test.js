import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import PipelineRunDashboard from './PipelineRunDashboard';

afterEach(() => {
  jest.restoreAllMocks();
});

test('shows only live-site stages and marks managed Nmap idle', () => {
  render(<PipelineRunDashboard />);
  expect(screen.getByRole('switch', { name: 'Enable Nmap' })).not.toBeChecked();
  fireEvent.change(screen.getByLabelText('Deployment Type'), {
    target: { value: 'managed' }
  });

  const stages = screen.getByLabelText('Pipeline stages');
  const orderedTitles = within(stages)
    .getAllByRole('heading', { level: 3 })
    .map((heading) => heading.textContent);

  expect(orderedTitles).toEqual([
    'Network Ports',
    'Web Vulnerabilities'
  ]);
  expect(within(stages).getByText('Skipped / Idle')).toBeInTheDocument();
  expect(screen.getByRole('switch', { name: 'Enable Nmap' })).toBeDisabled();
});

test('submits the selected deployment mode and displays consolidated stage results', async () => {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: true,
    json: async () => ({
      pipeline: {
        run_id: 'run-123',
        environment_type: 'managed',
        status: 'vulnerabilities_found',
        duration_seconds: 2.4,
        stages: {
          gitleaks: {
            status: 'not_requested',
            finding_count: 0,
            findings: [],
            reason: 'Source checks run in GitHub Actions and are not part of a live-site scan.'
          },
          trivy: {
            status: 'not_requested',
            finding_count: 0,
            findings: [],
            reason: 'Source checks run in GitHub Actions and are not part of a live-site scan.'
          },
          nmap: {
            status: 'skipped',
            reason: 'Bypassed / Idle (Managed Platform). Network port scanning is not run for managed deployments.',
            findings: []
          },
          zap: {
            status: 'vulnerabilities_found',
            finding_count: 1,
            target: 'http://127.0.0.1:8000',
            findings: [{
              name: 'Missing Content-Security-Policy header',
              description: 'The response has no content security policy.',
              severity: 'medium',
              url: 'http://127.0.0.1:8000/',
              solution: 'Add a Content-Security-Policy response header.'
            }]
          }
        },
        report_paths: {}
      }
    })
  });

  render(<PipelineRunDashboard />);
  fireEvent.click(screen.getByRole('switch', { name: 'Enable Nmap' }));
  fireEvent.change(screen.getByLabelText('Live website target'), {
    target: { value: 'http://127.0.0.1:8000' }
  });
  fireEvent.change(screen.getByLabelText('Deployment Type'), {
    target: { value: 'managed' }
  });
  fireEvent.click(screen.getByRole('button', { name: 'Run Security Pipeline' }));

  expect(await screen.findAllByText('Vulnerabilities Found')).not.toHaveLength(0);
  expect(screen.queryByText(/Source checks run in GitHub Actions/)).not.toBeInTheDocument();
  expect(screen.getByText(/Missing Content-Security-Policy header/)).toBeInTheDocument();
  expect(screen.getByText('Add a Content-Security-Policy response header.')).toBeInTheDocument();
  expect(screen.getAllByText(/Bypassed \/ Idle \(Managed Platform\)/).length).toBeGreaterThan(0);
  await waitFor(() => {
    expect(screen.getByRole('button', { name: 'Run Security Pipeline' })).toBeEnabled();
  });

  expect(global.fetch).toHaveBeenCalledWith(
    'http://localhost:8000/api/pipeline',
    expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        target: 'http://127.0.0.1:8000',
        environmentType: 'managed',
        nmapEnabled: false
      })
    })
  );
});

test('sends an enabled Nmap stage only after the user turns it on', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: true,
    json: async () => ({
      pipeline: {
        run_id: 'nmap-run',
        environment_type: 'self_hosted',
        status: 'passed',
        duration_seconds: 1,
        stages: {
          nmap: { status: 'completed', findings: { open_ports: [] } },
          zap: { status: 'completed', findings: [] }
        }
      }
    })
  });

  render(<PipelineRunDashboard />);
  fireEvent.change(screen.getByLabelText('Live website target'), {
    target: { value: 'http://127.0.0.1:8000' }
  });
  fireEvent.click(screen.getByRole('switch', { name: 'Enable Nmap' }));
  fireEvent.click(screen.getByRole('button', { name: 'Run Security Pipeline' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      'http://localhost:8000/api/pipeline',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          target: 'http://127.0.0.1:8000',
          environmentType: 'self_hosted',
          nmapEnabled: true
        })
      })
    );
  });
});
