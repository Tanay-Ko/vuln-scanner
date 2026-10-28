const API_BASE_URL = (process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000')
  .replace(/\/+$/, '');

export async function apiRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, options);
  } catch (error) {
    if (error && error.name === 'AbortError') throw error;
    throw new Error('Unable to reach the scanner API. Confirm the backend is running.');
  }

  let payload;
  try {
    payload = await response.json();
  } catch (_) {
    payload = null;
  }
  if (!response.ok) {
    const detail = payload && (payload.detail || payload.error);
    const message = typeof detail === 'string'
      ? detail
      : Array.isArray(detail)
        ? detail.map((item) => item.msg).filter(Boolean).join('; ')
        : `Scanner API request failed (${response.status}).`;
    throw new Error(message);
  }
  return payload;
}

export function scan(target, scanType, { signal, timeLimit } = {}) {
  const body = { target, scanType };
  if (timeLimit !== undefined && timeLimit !== null) body.timeLimit = timeLimit;
  return apiRequest('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal
  });
}

export function runPipeline(target, environmentType, nmapEnabled, { signal } = {}) {
  return apiRequest('/api/pipeline', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, environmentType, nmapEnabled }),
    signal
  });
}

export function getVulnerabilities(options = {}) {
  return apiRequest('/api/vulnerabilities', options);
}

export function getRecommendations(port, options = {}) {
  return apiRequest(`/api/recommendations/${encodeURIComponent(port)}`, options);
}
