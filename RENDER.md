# Deploying to Render

This Blueprint deploys the published `main` branch and creates a fresh database.
It does not include uncommitted local changes or import local database files.

1. In Render, create a Blueprint using this repository and the `main` branch.
2. Select the paid Starter web-service plan. A persistent disk is required so
   hospital records survive redeployments and restarts.
3. After the first deploy, open the service's Environment settings and copy the
   generated `ADMIN_PASSWORD` value. Sign in with username `admin` and that
   password; keep it private.
4. Configure any optional integrations as environment variables in Render; do
   not put credentials in the repository.

The Blueprint generates `SECRET_KEY` and `ADMIN_PASSWORD` values. The startup
command stores the SQLite database on the persistent disk mounted at `/var/data`.
