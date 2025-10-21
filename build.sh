#!/usr/bin/env bash
# Exit on error
set -o errexit

# Upgrade pip and install packages from requirements.txt
pip install --upgrade pip
pip install -r requirements.txt

