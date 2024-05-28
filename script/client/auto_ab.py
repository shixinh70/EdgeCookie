import subprocess
import re
import time

# Initialize variables to store total time and average time
total_time = 0

# Run the ab command 10 times
for i in range(1, 100):
    # Run the ab command and capture the output
    output = subprocess.run(['ab', '-n', '1', 'http://10.19.0.3/'], capture_output=True, text=True).stdout
    # Use regular expression to extract the mean time
    mean_time = re.search(r'Time per request:\s+(\d+\.\d+)\s+\[ms\]', output).group(1)
    # Add the mean time to the total time
    total_time += float(mean_time)
    print(f"Mean time for request {i}: {mean_time} milliseconds")
    # Introduce a delay of 0.01 seconds
    # time.sleep()

# Calculate the average time
average_time = total_time / 100
print(f"Total average time: {average_time:.3f} milliseconds")
