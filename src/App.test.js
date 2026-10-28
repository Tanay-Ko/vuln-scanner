import { fireEvent, render, screen } from '@testing-library/react';
import App from './App';

test('keeps live-site scanning separate from repository source security', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: 'Continuous Security Pipeline' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Network Ports' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Web Vulnerabilities' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Secret Detection' })).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Dependency Scan' })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Source Security' }));
  expect(screen.getByRole('heading', { name: 'Source Security' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Gitleaks' })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Trivy' })).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Open GitHub Actions' })).toHaveAttribute(
    'href',
    'https://github.com/Tanay-Ko/vuln-scanner/actions/workflows/source-security.yml'
  );

  fireEvent.click(screen.getByRole('button', { name: 'Live-site Scan' }));
  expect(screen.getByRole('heading', { name: 'Network Ports' })).toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'Gitleaks' })).not.toBeInTheDocument();
});
