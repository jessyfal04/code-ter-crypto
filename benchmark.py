import os
import time
import threading
import psutil
import functools
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

def profile_and_monitor(func):
    """
    A decorator that profiles the function's execution time and memory usage,
    while concurrently monitoring the CPU busy percentage and memory usage over time.
    After execution, it prints the execution time, the maximum extra memory used,
    and the average CPU busy percentage, then plots and saves a graph with CPU busy percentage
    and memory usage over time.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Record initial memory usage and start time.
        process = psutil.Process()
        mem_before = process.memory_info().rss  # in bytes
        start_time = time.perf_counter()
        
        # Lists for storing monitoring data.
        monitor_times = []
        busy_percentages = []
        memory_usages = []  # Memory usage delta (current - mem_before)
        
        stop_monitoring = threading.Event()

        def monitor():
            monitor_start = time.perf_counter()
            # Continuously sample CPU busy percentage and memory usage.
            while not stop_monitoring.is_set():
                # psutil.cpu_times_percent waits for 0.1 seconds.
                cpu_times = psutil.cpu_times_percent(interval=0.1)
                current_time = time.perf_counter() - monitor_start
                current_memory = process.memory_info().rss - mem_before
                # Calculate busy percentage.
                busy = 100 - cpu_times.idle
                monitor_times.append(current_time)
                busy_percentages.append(busy)
                memory_usages.append(current_memory)
        
        # Start monitoring thread.
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

        # Execute the target function.
        result = func(*args, **kwargs)

        # Stop monitoring and wait for the thread to finish.
        stop_monitoring.set()
        monitor_thread.join()

        # Record end time.
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        # Compute maximum memory used during execution.
        max_memory_used = max(memory_usages) if memory_usages else 0
        
        # Compute the average CPU busy percentage.
        avg_cpu_busy = np.mean(busy_percentages) if busy_percentages else 0

        # Print the profiling results.
        print(f"Execution Time: {execution_time:.6f} seconds")
        print(f"Maximum Additional Memory Used During Execution: {max_memory_used} bytes")
        print(f"Average CPU Busy Percentage: {avg_cpu_busy:.2f}%")

        # Plot the CPU busy percentages and memory usage over time using dual y-axes.
        fig, ax1 = plt.subplots(figsize=(10, 5))

        color = 'tab:red'
        ax1.set_xlabel("Time (seconds)")
        ax1.set_ylabel("CPU Busy Percentage", color=color)
        ax1.plot(monitor_times, busy_percentages, label='CPU Busy %', color=color)
        ax1.tick_params(axis='y', labelcolor=color)
        ax1.grid(True)

        ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis
        color = 'tab:blue'
        ax2.set_ylabel("Memory Usage (bytes)", color=color)
        ax2.plot(monitor_times, memory_usages, label='Memory Usage', color=color)
        ax2.tick_params(axis='y', labelcolor=color)

        plt.title("CPU Busy Percentage and Memory Usage Over Time")
        fig.tight_layout()  # otherwise the right y-label is slightly clipped

        # Create directory for graphs if it doesn't exist.
        folder_name = "graphs"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Generate timestamp and file path.
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_path = os.path.join(folder_name, f"graph_{timestamp}.png")

        # Save the figure.
        fig.savefig(file_path)
        print(f"Graph saved to: {file_path}")

        plt.show()

        return result
    return wrapper

@profile_and_monitor
def big_dummy_function():
    """
    A dummy heavy function simulating intensive computation that also allocates additional memory.
    """
    total = 0
    # Allocate extra memory by creating a large list.
    extra_memory = [i for i in range(10**8)]  # This allocates additional memory.
    
    # Example of heavy computation using the allocated list.
    for value in extra_memory:
        total += value % 7

    return total

if __name__ == '__main__':
    result = big_dummy_function()
    print("Algorithm result:", result)
