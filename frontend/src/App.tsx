import { useEffect, useState } from 'react';
import './App.css';
import { api, type ScanListItem, type HealthResponse } from './lib/api';

function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [healthData, scansData] = await Promise.all([
          api.health(),
          api.listScans(5),
        ]);
        setHealth(healthData);
        setScans(scansData);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <header className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900">RedFixer</h1>
          <p className="mt-2 text-lg text-gray-600">
            RHEL 9 Vulnerability Assessment and Remediation Tool
          </p>
        </header>

        {loading && (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
            <p className="mt-4 text-gray-600">Loading...</p>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <h3 className="text-red-800 font-semibold">Error</h3>
            <p className="text-red-600 mt-1">{error}</p>
            <p className="text-sm text-red-500 mt-2">
              Make sure the backend API is running on http://localhost:8000
            </p>
          </div>
        )}

        {!loading && !error && health && (
          <>
            <div className="bg-white shadow rounded-lg p-6 mb-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">API Status</h2>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600">Status</p>
                  <p className="text-lg font-medium text-green-600">{health.status}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">Version</p>
                  <p className="text-lg font-medium text-gray-900">{health.version}</p>
                </div>
              </div>
            </div>

            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                Recent Scans ({scans.length})
              </h2>
              {scans.length === 0 ? (
                <p className="text-gray-600">No scans found. Use the CLI to create a scan:</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Scan ID
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Vulnerability
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Status
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Hosts
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Created
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scans.map((scan) => (
                        <tr key={scan.scan_id}>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">
                            {scan.scan_id.substring(0, 8)}...
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {scan.vuln_id}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              scan.status === 'completed' ? 'bg-green-100 text-green-800' :
                              scan.status === 'running' ? 'bg-blue-100 text-blue-800' :
                              scan.status === 'failed' ? 'bg-red-100 text-red-800' :
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {scan.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {scan.host_count}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {new Date(scan.created_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="mt-4 p-4 bg-blue-50 rounded-lg">
                <p className="text-sm text-blue-800">
                  <strong>Create a scan using the CLI:</strong>
                </p>
                <code className="block mt-2 p-2 bg-blue-100 rounded text-xs">
                  redfixer scan create CVE-2021-44228 --hosts localhost
                </code>
              </div>
            </div>
          </>
        )}

        <footer className="mt-12 text-center text-sm text-gray-500">
          <p>RedFixer v0.1.0 - Built with React 18.3.1 (Safe from CVE-2025-55182)</p>
          <p className="mt-1">Backend API + CLI fully functional</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
