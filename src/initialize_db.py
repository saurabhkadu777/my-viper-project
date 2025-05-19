#!/usr/bin/env python3
"""
VIPER - Database Initialization Script

This script initializes the database schema, ensuring all required columns are present.
It's useful when adding new features that require database schema changes.
"""
import os
import sys

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.database_handler import initialize_db

if __name__ == "__main__":
    print("Initializing VIPER database schema...")
    initialize_db()
    print("Database schema initialization complete.")
    print("The database now includes all required columns, including exploit-related columns.")
