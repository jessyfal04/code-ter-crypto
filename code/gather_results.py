import os
import shutil
from pathlib import Path

def gather_aggregated_files():
    # Base directories
    base_dir = "results_profile"
    vm_patterns = [
        "vm1/*",
        "vm2/*"
    ]
    output_dir = os.path.join(base_dir, "grapped")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Counter for unique file names
    file_counter = 1
    
    # Process each VM pattern
    for vm_pattern in vm_patterns:
        # Get all matching directories
        vm_path = os.path.join(base_dir, vm_pattern)
        test_run_dirs = [d for d in Path(base_dir).glob(vm_pattern)]
        
        if not test_run_dirs:
            print(f"Warning: No directories matching {vm_path} found. Skipping...")
            continue
        
        # Process each test run directory
        for test_run_dir in test_run_dirs:
            # Walk through all subdirectories
            for root, dirs, files in os.walk(test_run_dir):
                for file in files:
                    if file == "aggregated.md":
                        # Get the full path of the source file
                        source_path = os.path.join(root, file)
                        
                        # Create a unique name for the destination file
                        # Include the test run directory name and a counter to avoid duplicates
                        test_run_name = os.path.basename(test_run_dir)
                        dest_filename = f"aggregated_{test_run_name}_{file_counter}.md"
                        dest_path = os.path.join(output_dir, dest_filename)
                        
                        # Copy the file
                        shutil.copy2(source_path, dest_path)
                        print(f"Copied {source_path} to {dest_path}")
                        
                        file_counter += 1

if __name__ == "__main__":
    gather_aggregated_files()
    print("Finished gathering aggregated.md files") 