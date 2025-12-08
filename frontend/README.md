# RedFixer Frontend

Minimal viable React 18.3.1 frontend for the RedFixer vulnerability assessment tool.

## Security Note

Built with **React 18.3.1** - Safe from CVE-2025-55182 (Critical RCE vulnerability in React 19 Server Components).

## Features

- Dashboard showing API health status
- Recent scans list with real-time data
- Clean, responsive UI with Tailwind CSS
- API integration with error handling
- TypeScript for type safety

## Development

```bash
npm install
npm run dev
```

Default URL: http://localhost:5173

## API Configuration

Connects to backend API at `http://localhost:8000/api/v1` by default.
