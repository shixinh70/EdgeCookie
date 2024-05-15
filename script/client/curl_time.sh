#!/bin/bash

# Check if correct parameters are provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <N seconds>"
    exit 1
fi

# Set counter and total time
count=0
total_time=0

# Iterate for N seconds
for (( i=0; i<$1; i++ )); do
    # Calculate time using curl
    result=$(curl -so /dev/null -w '%{time_total}\n' 10.19.0.3)

    # Add time to total time
    total_time=$(echo "$total_time + $result" | bc)

    # Increment counter
    count=$((count+1))

    # Pause for one second
    sleep 1
done

# Calculate average time
average_time=$(echo "scale=7; $total_time / $count" | bc)

# Output results
echo "Total time: $total_time seconds"
echo "Average time: $average_time seconds"