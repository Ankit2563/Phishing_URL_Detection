import csv

# Input CSV file name
input_file = 'nephi.csv'

# Output CSV file name with added index
output_file = 'mophi.csv'

# Read the existing CSV file and add an index column
with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    header = next(reader)

    # Add an "index" header to the existing header
    header = ['index'] + header

    writer = csv.writer(outfile)
    writer.writerow(header)

    # Write rows with added index
    for i, row in enumerate(reader):
        writer.writerow([i] + row)
