#!/usr/bin/env python3
"""Simple utility script for file operations"""

import os
from pathlib import Path

def list_files(directory):
    """List all files in directory"""
    path = Path(directory)
    return [f.name for f in path.iterdir() if f.is_file()]

def get_file_size(file_path):
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def main():
    current_dir = "."
    files = list_files(current_dir)
    print(f"Found {len(files)} files")
    
    for file in files[:5]:  # Show first 5 files
        size = get_file_size(file)
        print(f"{file}: {size} bytes")

if __name__ == "__main__":
    main()
