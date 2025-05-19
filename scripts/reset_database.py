#!/usr/bin/env python3
"""
VIPER - Database Reset Script

This script deletes the existing database file and initializes a fresh one.
Use with caution as it will delete all stored CVE data.
"""
import os
import shutil
import sys

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config import get_db_file_name
from src.utils.database_handler import initialize_db


def reset_database():
    db_path = get_db_file_name()

    print(f"About to delete and reinitialize database at: {db_path}")

    # Check if the database file exists
    if os.path.exists(db_path):
        # Make a backup of the current database
        backup_path = f"{db_path}.backup"
        print(f"Creating backup at: {backup_path}")
        shutil.copy2(db_path, backup_path)

        # Delete the existing database file
        print("Deleting existing database file...")
        os.remove(db_path)
    else:
        print("No existing database file found.")

    # Initialize a fresh database
    print("Initializing fresh database...")
    initialize_db()

    print("Database reset complete.")
    print(f"A backup of the old database was saved at: {db_path}.backup")


if __name__ == "__main__":
    confirm = input("This will delete all data in the VIPER database. Are you sure? (yes/no): ")
    if confirm.lower() in ["yes", "y"]:
        reset_database()
    else:
        print("Database reset cancelled.")
