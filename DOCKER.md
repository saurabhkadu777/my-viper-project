# Running VIPER in Docker

This document explains how to run the VIPER Vulnerability Intelligence Platform using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose installed on your system

## Setup

1. Copy the example environment file and set your API keys:

```bash
cp .env.example .env
```

2. Edit the `.env` file to add your API keys:
   - `GEMINI_API_KEY`: Your Google Gemini API key
   - `GITHUB_TOKEN`: Your GitHub personal access token
   - Other configuration as needed

## Running with Docker Compose



1. Start the application:

```bash
docker-compose up -d
```

2. Access the VIPER dashboard at: http://localhost:8501

3. Stop the application:

```bash
docker-compose down
```

## Data Persistence

The Docker setup includes a volume mount for the `/app/data` directory, which stores:

- SQLite database containing vulnerability data
- Any other persisted data

The data will be stored in the `./data` directory on your host machine.

## Environment Variables

You can customize the application by setting environment variables in the `.env` file or directly in the `docker-compose.yml` file.

Key variables:

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Google Gemini API key for AI analysis |
| `GITHUB_TOKEN` | GitHub token for searching exploit repositories |
| `DB_FILE_NAME` | Path to the SQLite database file |
| `LOG_LEVEL` | Logging level (INFO, DEBUG, etc.) |

## Building the Image Manually

If you need to build the Docker image manually:

```bash
docker build -t viper-app .
```

Then run it:

```bash
docker run -p 8501:8501 -v ./data:/app/data viper-app
```

## Troubleshooting

1. If you can't access the app, check if it's running:

```bash
docker ps
```

2. Check application logs:

```bash
docker-compose logs viper-app
```

3. If you're having database issues, check the volume permissions:

```bash
ls -la ./data
```
