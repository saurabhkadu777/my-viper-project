#!/bin/bash

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Check if dependencies are installed
if ! command -v streamlit &> /dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Run the Streamlit dashboard
echo "Starting VIPER CTI Dashboard..."
streamlit run src/dashboard/app.py
