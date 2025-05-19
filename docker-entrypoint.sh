#!/bin/bash
set -e

echo "Running database initialization..."
python src/initialize_db.py

echo "Starting Streamlit application..."
exec streamlit run src/dashboard/app.py --server.port=8501 --server.address=0.0.0.0
