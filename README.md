# Email Platform Detector

This repository now separates the API and the static site so the project works with both GitHub Pages and any Node-compatible host.

## Folder layout
- `backend/` – Express API that performs DNS lookups and hosts the static files when running locally.
- `docs/` – Static site that GitHub Pages publishes from the `main` branch.
- `.github/workflows/` – Continuous deployment for the API (`deploy.yml`) and GitHub Pages (`pages.yml`).

## Getting started
1. Install API dependencies: `cd backend && npm install`.
2. Run the API locally: `npm start`. The server reads configuration from `.env` (see `.env.example` if present) and serves the site from `../docs`.
3. Update the static site inside `docs/`; commit changes to trigger the Pages workflow.

## Deployment
- **GitHub Pages**: pushes affecting `docs/` run `.github/workflows/pages.yml`, which uploads the folder to GitHub Pages.
- **Backend**: `.github/workflows/deploy.yml` keeps installing dependencies from `backend/`. Add a real deploy step (Render, Railway, etc.) and set the required secrets before enabling automatic deploys.

## Notes
- `.gitignore` now ignores environment files and `node_modules/`.
- If you publish the API to GitHub Packages later, update `backend/package.json` with your scoped package name (for example `@saleudon1/email-platform-detector-backend`).
