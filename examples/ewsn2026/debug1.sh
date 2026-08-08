#!/bin/bash

# Usage: ./check_ids.sh /path/to/yourfile.csv
CSV_FILE="$1"

if [ -z "$CSV_FILE" ]; then
  echo "Please provide the path to the CSV file."
  exit 1
fi

if [ ! -f "$CSV_FILE" ]; then
  echo "File not found: $CSV_FILE"
  exit 1
fi

# Define the set of IDs
addresses=("68e5" "6910" "68c6" "6981" "696c" "691b" "6971" "6e71" "695f" "6df1" "6932" "692f" "6dba" "6904" "694d" "692e" "68f7" "6949" "6dd0" "6960" "68e7" "68c4" "6921" "6e63" "68d1" "692b" "6964" "6973" "6e8f" "6dc2")

# Get the last 5000 lines of the CSV file
last_lines=$(tail -n 5000 "$CSV_FILE")

# Check for each pattern
for x in "${addresses[@]}"; do
  pattern="openmoteb-.*;r;.*;${x}"
  if echo "$last_lines" | grep -qE "$pattern"; then
    echo "Found: openmoteb with ID $x"
  else
    echo "Not found: openmoteb with ID $x"
  fi
done