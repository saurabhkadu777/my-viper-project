#!/usr/bin/env python3
"""
VIPER - Database Initialization Script

This script initializes the database structure, handling existing
columns gracefully to prevent "duplicate column" errors.
"""
import logging
import os
import sys

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.database_handler import initialize_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)

logger = logging.getLogger(__name__)


def main():
    logger.info("Initializing VIPER database...")
    try:
        initialize_db()
        logger.info("Database initialization completed successfully.")
    except Exception as e:
        logger.error(f"Error during database initialization: {str(e)}")
        # Exit with non-zero status but don't completely fail the container
        sys.exit(1)


if __name__ == "__main__":
    main()
