import pandas as pd
import os
from datetime import datetime

# Define the paths for the folder containing the scenario logs and the folder to save the combined dataset
scenario_logs_folder = "scenario_logs"
datasets_folder = "datasets"

# List all files in the scenario_logs folder
scenario_files = os.listdir(scenario_logs_folder)

# Initialize an empty list to store dataframes
dfs = []

# Loop through each file in the folder
for file in scenario_files:
    # Check if the file is a CSV file
    if file.endswith(".csv"):
        # Read the CSV data into a dataframe
        file_path = os.path.join(scenario_logs_folder, file)
        df = pd.read_csv(file_path)

        # Append the dataframe to the list
        dfs.append(df)

# Combine all dataframes into one
combined_df = pd.concat(dfs, ignore_index=True)

# Get the current timestamp to create a unique file name
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define the path to save the new combined dataset with the timestamp in the filename
output_file_path = os.path.join(datasets_folder, f"combined_dataset_{timestamp}.csv")

# Save the combined dataframe to a new CSV file
combined_df.to_csv(output_file_path, index=False)

# Print the path where the dataset was saved
print(f"Combined dataset saved as: {output_file_path}")
