#!/bin/bash

# Create temp directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Clone and build
echo "Cloning repository..."
git clone https://github.com/0xnoid/vhsrekon
cd vhsrekon

echo "Building Docker image..."
docker build -t vhsrekon .

# Cleanup
cd ..
rm -rf "$TEMP_DIR"

echo "Installation complete. Run with: docker run -it -v \$(pwd):/data vhsrekon [COMMAND]"