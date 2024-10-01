#!/bin/bash

# Navigate to the project directory
cd ~/6130project_refactored

# Stop and remove existing containers
docker compose down --remove-orphans

# Build and run the containers without using cache
docker compose up -d --build --force-recreate --no-cache --remove-orphans
