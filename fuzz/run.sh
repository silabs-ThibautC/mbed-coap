#!/bin/bash

# A simple script to build and run the fuzzer.

# Change to the script's directory. This allows the script to be run from anywhere.
cd "$(dirname "$0")"

# Exit on error
set -e

# --- Compilation ---
echo "[*] Building the fuzzer..."
make

# --- Fuzzing ---
echo "[*] Starting the fuzzer..."
afl-fuzz -i seeds -o findings -- ./parser_fuzzer 