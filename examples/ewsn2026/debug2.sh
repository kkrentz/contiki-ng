#!/bin/bash

# Usage: ./check.sh /path/to/yourfile.csv
CSV_FILE="$1"

if [ -z "$CSV_FILE" ]; then
  echo "Please provide the path to the CSV file."
  exit 1
fi

if [ ! -f "$CSV_FILE" ]; then
  echo "File not found: $CSV_FILE"
  exit 1
fi

# Define the set of numbers
motes=(1 3 4 5 6 9 10 11 12 14 15 16 17 19 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36)

# Get the last 100 lines of the CSV file
last_lines=$(tail -n 1000 "$CSV_FILE")

# Check for each pattern
for i in "${motes[@]}"; do
  pattern="openmoteb-${i};\[INFO: cc2538-rf \] Set Channel"
  if echo "$last_lines" | grep -q "$pattern"; then
    echo "Found: openmoteb-${i} set channel"
  else
    echo "Not found: openmoteb-${i} did not set channel"
  fi
done