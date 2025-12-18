#!/bin/bash
set -e

# Clean (inside syz-env)
./tools/syz-env make clean

# Build syz-logparser
./tools/syz-env go build -o bin/syz-logparser tools/syz-logparser/logparser.go
