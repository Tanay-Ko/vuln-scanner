import { apiRequest, runPipeline, scan } from './client';

afterEach(() => {
  jest.restoreAllMocks();
});

test('scan uses the shared API client and sends scan parameters', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: true,
    json: async () => ({ target: '127.0.0.1', open_ports: [] })
  });
  const controller = new AbortController();

  await scan('127.0.0.1', 'basic', { signal: controller.signal, timeLimit: 60 });

  expect(fetchMock).toHaveBeenCalledWith(
    'http://localhost:8000/api/scan',
    expect.objectContaining({
      method: 'POST',
      signal: controller.signal,
      body: JSON.stringify({ target: '127.0.0.1', scanType: 'basic', timeLimit: 60 })
    })
  );
});

test('pipeline request includes the explicit Nmap toggle state', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: true,
    json: async () => ({ pipeline: { stages: {} } })
  });

  await runPipeline('https://example.com', 'self_hosted', true);

  expect(fetchMock).toHaveBeenCalledWith(
    'http://localhost:8000/api/pipeline',
    expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        target: 'https://example.com',
        environmentType: 'self_hosted',
        nmapEnabled: true
      })
    })
  );
});

test('API validation details are surfaced as readable errors', async () => {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: false,
    status: 422,
    json: async () => ({
      detail: [{ msg: 'Network scan target must be a valid IP address or hostname.' }]
    })
  });

  await expect(apiRequest('/api/scan')).rejects.toThrow(
    'Network scan target must be a valid IP address or hostname.'
  );
});

test('network failures produce a consistent backend-unavailable message', async () => {
  jest.spyOn(global, 'fetch').mockRejectedValue(new TypeError('network down'));

  await expect(apiRequest('/api/vulnerabilities')).rejects.toThrow(
    'Unable to reach the scanner API. Confirm the backend is running.'
  );
});
