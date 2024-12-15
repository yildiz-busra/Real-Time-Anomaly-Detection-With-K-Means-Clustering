import re

# Input and output file paths
input_file = "detailedActivity.log"
output_file = "cleanedActivity.log"

# Function to clean and format log lines
def clean_log_line(line):
    # Remove 'time:' and 'summary:' fields
    line = re.sub(r"time: [^,]+, ", "", line)  # Remove 'time:' and its value
    line = re.sub(r"summary: [^,]+, ", "", line)  # Remove 'summary:' and its value
   
    # Replace '-' with ','
    line = line.replace(" - ", ", ")
    
    return line

# Process the file
with open(input_file, "r") as infile, open(output_file, "w") as outfile:
    for line in infile:
        cleaned_line = clean_log_line(line)
        outfile.write(cleaned_line)

print(f"Cleaned and formatted log saved to {output_file}")
