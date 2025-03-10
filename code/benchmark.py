import os
import time
import threading
import psutil
import functools
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import gc

STEP_SECOND = 0.5  # Sampling interval for CPU busy percentage in seconds


PLOT = False    # Set to True to enable plotting
BATTERY = False  # Set to True to enable battery monitoring
COMBINED = False # Set to True to enable the combined graph
NETWORK = True  # Set to True to enable network monitoring

network_bytes_sent = 0 # Global variable to store network bytes sent
network_bytes_received = 0 # Global variable to store network bytes received


def profile_and_monitor(func):
    """
    A decorator that profiles the function's execution time and memory usage,
    while concurrently monitoring the CPU busy percentage, memory usage, and battery level (if enabled) over time.
    After execution, it prints the execution time, the maximum extra memory used,
    and the average CPU busy percentage, then plots and saves graphs with system metrics over time.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):

        ### FOLDER AND LOG FUNCTIONS

        # Create timestamped folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        folder_name = f"results_profile/{func.__name__}_{timestamp}"
        os.makedirs(folder_name, exist_ok=True)
        
        # Log file
        log_file = os.path.join(folder_name, "print.md")
        
        def log_message(message):
            print(message)
            with open(log_file, "a") as f:
                f.write(message + "\n")

        ### PRE MONITORING

        log_message(f"# Function and Args")
        log_message(f"- Function: {func.__name__}")
        log_message(f"- Arguments: {args}")
        log_message(f"- Keyword Arguments: {kwargs}")

        # Lists for storing monitoring data.
        monitor_times = []         # Time in seconds
        busy_percentages = []      # CPU busy percentage (100 - idle)
        memory_usages = []         # Memory usage delta (current - mem_before)
        battery_percentages = [] if BATTERY else None
        network_sent = [] if NETWORK else None
        network_received = [] if NETWORK else None

        # Record initial process state
        process = psutil.Process()
        start_time = time.perf_counter()
        
        stop_monitoring = threading.Event()

        def monitor():
            monitor_start = time.perf_counter()
            mem_before = process.memory_info().rss  # in bytes
            if BATTERY:
                battery_sensor = psutil.sensors_battery()
                battery_before = battery_sensor.percent if battery_sensor is not None else None

            # Continuously sample
            while not stop_monitoring.is_set():
                cpu_times = psutil.cpu_times_percent(interval=STEP_SECOND)
                current_time = time.perf_counter() - monitor_start
                current_memory = process.memory_info().rss - mem_before

                busy = 100 - cpu_times.idle
                monitor_times.append(current_time)
                busy_percentages.append(busy)
                memory_usages.append(current_memory)
                if BATTERY and battery_before is not None:
                    # Record current battery percentage (if sensor available)
                    current_battery = psutil.sensors_battery().percent
                    battery_percentages.append(current_battery)
                if NETWORK:
                    network_sent.append(network_bytes_sent)
                    network_received.append(network_bytes_received)
        
        ### MONITORING 

        # Start monitoring thread.
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

        # Execute the target function.
        result = func(*args, **kwargs)

        # Stop monitoring and wait for the thread to finish.
        stop_monitoring.set()
        monitor_thread.join()

        ### POST MONITORING
        def format_bytes(num_bytes):
            """
            Convert a number of bytes into a human readable string.
            """
            for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
                if num_bytes < 1024:
                    return f"{num_bytes:.2f} {unit}"
                num_bytes /= 1024

        # Execution Time
        end_time = time.perf_counter()
        execution_time = end_time - start_time
        
        # Memory Usage
        avg_memory_used = np.mean(memory_usages) if memory_usages else 0
        max_memory_used = max(memory_usages) if memory_usages else 0
        min_memory_used = min(memory_usages) if memory_usages else 0
        
        # CPU Busy Percentage
        avg_cpu_busy = np.mean(busy_percentages) if busy_percentages else 0
        max_cpu_busy = max(busy_percentages) if busy_percentages else 0
        min_cpu_busy = min(busy_percentages) if busy_percentages else 0

        log_message(f"# Profiling Results")

        log_message(f"## Execution Time")
        log_message(f"- Execution Time: {execution_time:.6f} seconds")

        log_message(f"## Additional Memory Usage")
        log_message(f"- Average Memory Usage: {format_bytes(avg_memory_used)}")
        log_message(f"- Max Memory Usage: {format_bytes(max_memory_used)}")
        log_message(f"- Min Memory Usage: {format_bytes(min_memory_used)}")
        
        log_message(f"## CPU Busy Percentage")
        log_message(f"- Average CPU Busy Percentage: {avg_cpu_busy:.2f}%")
        log_message(f"- Max CPU Busy Percentage: {max_cpu_busy:.2f}%")
        log_message(f"- Min CPU Busy Percentage: {min_cpu_busy:.2f}%")

        if BATTERY and battery_percentages:
            avg_battery = np.mean(battery_percentages)
            max_battery = max(battery_percentages)
            min_battery = min(battery_percentages)
            log_message(f"## Battery Percentage")
            log_message(f"- Average Battery Percentage: {avg_battery:.2f}%")
            log_message(f"- Max Battery Percentage: {max_battery:.2f}%")
            log_message(f"- Min Battery Percentage: {min_battery:.2f}%")

        if NETWORK:
            # After stopping the monitor thread in benchmark.py
            log_message(f"## Network Metrics")
            final_sent = network_sent[-1] if network_sent else 0
            final_received = network_received[-1] if network_received else 0
            log_message(f"- Total Bytes Sent: {format_bytes(final_sent)}")
            log_message(f"- Total Bytes Received: {format_bytes(final_received)}")


        ### PLOT

        def plot_graph(x_data, y_data_list, x_label, y_labels, title, colors, filename):
            fig, ax1 = plt.subplots(figsize=(10, 5))
            ax1.set_xlabel(x_label)
            
            axes = [ax1]
            for i, (y_data, y_label, color) in enumerate(zip(y_data_list, y_labels, colors)):
                if i == 0:
                    ax = ax1
                else:
                    ax = ax1.twinx()
                    ax.spines['right'].set_position(('outward', 60 * (i - 1)))
                
                ax.set_ylabel(y_label, color=color)
                ax.plot(x_data, y_data, label=y_label, color=color)
                ax.tick_params(axis='y', labelcolor=color)
                axes.append(ax)
            
            plt.title(title)
            fig.tight_layout()
            
            file_path = os.path.join(folder_name, f"graph_{filename}")
            fig.savefig(file_path)
            print(f"Saving graph {title} to: {file_path}")
            
            if PLOT:
                plt.show()

        # Plot CPU Busy Percentage graph.
        plot_graph(monitor_times, [busy_percentages],
                   "Time (seconds)", ["CPU Busy Percentage"],
                   "CPU Busy Percentage Over Time", ['tab:red'], "graph_cpu.png")
        # Plot Memory Usage graph.
        plot_graph(monitor_times, [memory_usages],
                   "Time (seconds)", ["Memory Usage (bytes)"],
                   "Memory Usage Over Time", ['tab:blue'], "graph_ram.png")
        # Plot Battery Percentage graph if battery monitoring is enabled.
        if BATTERY and battery_percentages:
            plot_graph(monitor_times, [battery_percentages],
                       "Time (seconds)", ["Battery Percentage"],
                       "Battery Percentage Over Time", ['tab:green'], "graph_battery.png")
            
        if NETWORK:
            plot_graph(monitor_times, [network_sent],
                       "Time (seconds)", ["Network Bytes Sent"],
                       "Network Bytes Over Time", ['tab:pink'], "graph_network_sent.png")
            
            plot_graph(monitor_times, [network_received],
                       "Time (seconds)", ["Network Bytes Received"],
                       "Network Bytes Over Time", ['tab:purple'], "graph_network_received.png")
        
        # Plot Combined graph:
        if COMBINED :
            if BATTERY and battery_percentages:
                plot_graph(monitor_times, [busy_percentages, memory_usages, battery_percentages],
                        "Time (seconds)",
                        ["CPU Busy Percentage", "Memory Usage (bytes)", "Battery Percentage", "Network Bytes Sent", "Network Bytes Received"],
                        "System Stats Over Time", ['tab:red', 'tab:blue', 'tab:green', 'tab:pink', 'tab:purple'], "graph_combined.png")
            
            else:
                plot_graph(monitor_times, [busy_percentages, memory_usages],
                        "Time (seconds)",
                        ["CPU Busy Percentage", "Memory Usage (bytes), Network Bytes Sent, Network Bytes Received"],
                        "System Stats Over Time", ['tab:red', 'tab:blue', 'tab:pink', 'tab:purple'], "graph_combined.png")
            
            if NETWORK:
                plot_graph(monitor_times, [network_sent, network_received],
                        "Time (seconds)", ["Network Bytes Sent", "Network Bytes Received"],
                        "Network Bytes Over Time", ['tab:pink', 'tab:purple'], "graph_combined_network.png")
        
        
        ### RESULT

        log_message(f"# Algorithm Result")
        log_message(f"- Result: {result}")
        
        return result
    return wrapper

@profile_and_monitor
def dummy(range_mod=2**24, modulo=7, range_sum=2**8):
    """
    A dummy heavy function simulating intensive computation that also allocates additional memory.
    """
    gc.collect()

    totalMod = 0
    totalSum = 0

    # Modulo computation
    extra_memory = [i for i in range(range_mod)]
    for value in extra_memory:
        totalMod += value % modulo
    del extra_memory
    gc.collect()

    # Sum computation
    time.sleep(2)
    extra_memory = [i for i in range(range_sum)]
    totalSum = sum(extra_memory)
    del extra_memory
    gc.collect()

    time.sleep(1)
    return (totalMod, totalSum)

if __name__ == '__main__':
    result = dummy(range_mod=2**27, modulo=7, range_sum=2**28)
    print("Algorithm result:", result)
