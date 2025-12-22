# PassKey Sample Frontend

A React + TypeScript frontend application built with Vite, using React Query and Axios for API communication.

## Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

## Docker

The frontend is containerized with nginx serving the built application over HTTPS.

```bash
docker-compose up frontend
```

## Environment Variables

- `VITE_API_BASE_URL`: Backend API base URL (default: `https://localhost:5001`)

