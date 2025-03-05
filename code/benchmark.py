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
PLOT = False  # Set to False to disable plotting

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

        ### FOLDER AND LOG FUNCTIONS

        # Create timestamped folder
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        folder_name = f"../results_profile/{func.__name__}_{timestamp}"
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
        monitor_times = [] # Time in seconds
        busy_percentages = [] # CPU busy percentage (100 - idle)
        memory_usages = []  # Memory usage delta (current - mem_before)
        #battery_percentages = [] # Battery percentage delta (current - battery_before)

        # Record initial 
        process = psutil.Process()
        start_time = time.perf_counter()
        
        stop_monitoring = threading.Event()

        def monitor():
            monitor_start = time.perf_counter()
            mem_before = process.memory_info().rss  # in bytes
            #battery_before = psutil.sensors_battery().percent

            # Continuously sample
            while not stop_monitoring.is_set():
                # psutil.cpu_times_percent waits for STEP_SECOND seconds.
                cpu_times = psutil.cpu_times_percent(interval=STEP_SECOND)
                current_time = time.perf_counter() - monitor_start
                current_memory = process.memory_info().rss - mem_before
                #current_battery = psutil.sensors_battery().percent - battery_before

                # Calculate busy percentage.
                busy = 100 - cpu_times.idle
                monitor_times.append(current_time)
                busy_percentages.append(busy)
                memory_usages.append(current_memory)
                #battery_percentages.append(current_battery)
        
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

        #print(battery_percentages)

        ## Calculate
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

        # Battery Percentage
        #last_battery = battery_percentages[-1] if battery_percentages else 0

        ## Logs
        # Log the profiling results.
        log_message(f"# Profiling Results")

        log_message(f"## Execution Time")
        log_message(f"- Execution Time: {execution_time:.6f} seconds")

        log_message(f"## Additional Memory Usage")
        log_message(f"- Average Memory Usage: {avg_memory_used / 1024:.2f} KB")
        log_message(f"- Max Memory Usage: {max_memory_used / 1024:.2f} KB")
        log_message(f"- Min Memory Usage: {min_memory_used / 1024:.2f} KB")
        
        log_message(f"## CPU Busy Percentage")
        log_message(f"- Average CPU Busy Percentage: {avg_cpu_busy:.2f}%")
        log_message(f"- Max CPU Busy Percentage: {max_cpu_busy:.2f}%")
        log_message(f"- Min CPU Busy Percentage: {min_cpu_busy:.2f}%")

        #log_message(f"## Battery Percentage")
        #log_message(f"- Last Battery: {last_battery:.10f}% pts")

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

        plot_graph(monitor_times, [busy_percentages],"Time (seconds)", ["CPU Busy Percentage"], "CPU Busy Percentage Over Time", ['tab:red'], "graph_cpu.png")
        plot_graph(monitor_times, [memory_usages],"Time (seconds)", ["Memory Usage (bytes)"], "Memory Usage Over Time", ['tab:blue'], "graph_ram.png")
        #plot_graph(monitor_times, [battery_percentages],"Time (seconds)", ["Battery Percentage"], "Battery Percentage Over Time", ['tab:green'], "graph_battery.png")
        #plot_graph(monitor_times, [busy_percentages, memory_usages, battery_percentages],"Time (seconds)", ["CPU Busy Percentage", "Memory Usage (bytes)", "Battery Percentage"], "System Stats Over Time", ['tab:red', 'tab:blue', 'tab:green'], "graph_all.png")
        plot_graph(monitor_times, [busy_percentages, memory_usages],"Time (seconds)", ["CPU Busy Percentage", "Memory Usage (bytes)"], "System Stats Over Time", ['tab:red', 'tab:blue'], "graph_all.png")
        
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

    # Modulo
    extra_memory = [i for i in range(range_mod)]
    for value in extra_memory:
        totalMod += value % modulo
    del extra_memory
    gc.collect()

    # Sum
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
