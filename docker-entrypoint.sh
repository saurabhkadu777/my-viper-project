#!/bin/bash
set -e

echo "Running database initialization..."
# Try to initialize the database, but don't fail if there are non-critical errors
python src/initialize_db.py || {
    echo "Warning: Database initialization completed with some warnings."
    echo "This is usually OK for existing databases and duplicate column errors."
    echo ""
    echo "If you need to completely reset the database due to persistent issues, you can:"
    echo "1. Use the database reset script inside the container:"
    echo "   docker exec -it viper python scripts/reset_database.py"
    echo ""
    echo "2. Or remove the volume and restart:"
    echo "   docker-compose down -v"
    echo "   docker-compose up"
}

echo "Starting Streamlit application..."
exec streamlit run src/dashboard/app.py --server.port=8501 --server.address=0.0.0.0
