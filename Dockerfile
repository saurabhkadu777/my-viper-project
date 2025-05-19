FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Make sure the .streamlit directory is copied
RUN mkdir -p /app/.streamlit
COPY .streamlit/config.toml /app/.streamlit/config.toml

# Expose the Streamlit port
EXPOSE 8501

# Set environment variables
ENV PYTHONPATH=/app
# Remove conflicting Streamlit environment variables
# ENV STREAMLIT_SERVER_PORT=8501
# ENV STREAMLIT_SERVER_HEADLESS=true
# ENV STREAMLIT_SERVER_ENABLE_CORS=false

# Set database file path
ENV DB_FILE_NAME=/app/data/viper.db

# Create data directory
RUN mkdir -p /app/data

# Make entrypoint script executable
RUN chmod +x /app/docker-entrypoint.sh

# Use entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]
