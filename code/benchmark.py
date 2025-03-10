import os
import time
import threading
import psutil
import functools
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import gc
from colorama import Fore
#import pyRAPL.pyRAPL  # Not used for now

STEP_SECOND = 0.5  # Sampling interval for CPU busy percentage in seconds

PLOT_PRINT = False    # Set to True to enable plotting and printing
BATTERY = False  # Set to True to enable battery monitoring

network_bytes_sent = 0  # Global variable to store network bytes sent
network_bytes_received = 0  # Global variable to store network bytes received

def profile_and_monitor(number=1):
    """
    A parameterized decorator that profiles the function's execution time and memory usage,
    while concurrently monitoring CPU busy percentage, memory usage, and battery level (if enabled)
    over time. When number > 1, it runs the function multiple times and, at the end, logs aggregated
    statistics (min of the mins, max of the maxs, and avg of the avgs for each metric) as well as 
    averaged time-series graphs.
    """

    # A unified plot_graph function that saves plots to the given folder.
    def plot_graph(x_data, y_data_list, x_label, y_labels, title, colors, filename, folder):
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
        file_path = os.path.join(folder, f"graph_{filename}")
        fig.savefig(file_path)
        print(Fore.GREEN + f"Saving graph {title} to: {file_path}")
        
        if PLOT_PRINT:
            plt.show()
    
    # A unified log_message function that prints and logs messages to the given file.
    def log_message(message, log_file):
        with open(log_file, "a") as f:
            f.write(message + "\n")

        if PLOT_PRINT:
            print(Fore.GREEN + message)

    # A utility function to convert bytes into human readable format.
    def format_bytes(num_bytes):
        """
        Convert a number of bytes into a human readable string.
        """
        sign = "-" if num_bytes < 0 else ""
        num = abs(num_bytes)
        for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024:
                return f"{sign}{num:.2f} {unit}"
            num /= 1024

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create a main timestamped folder for aggregated results.
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            main_folder = f"results_profile/{func.__name__}_{timestamp}"
            os.makedirs(main_folder, exist_ok=True)
            
            # Aggregated lists for metrics across runs (for averaged graphs)
            aggregated_monitor_times = []
            aggregated_busy_percentages = []
            aggregated_memory_usages = []
            if BATTERY:
                aggregated_battery_percentages = []
            
            aggregated_network_sent = []
            aggregated_network_received = []
            
            # Initialize lists to store aggregated summary metrics over runs.
            all_execution_times = []
            all_avg_memory_used = []
            all_max_memory_used = []
            all_min_memory_used = []
            all_avg_cpu_busy = []
            all_max_cpu_busy = []
            all_min_cpu_busy = []

            if BATTERY:
                all_avg_battery = []
                all_max_battery = []
                all_min_battery = []

            all_final_sent = []
            all_final_received = []
            
            last_result = None  # To eventually return the result (from the last run)
            
            # Run the function "number" times.
            for run in range(number):
                # Create a subfolder for this run.
                run_folder = os.path.join(main_folder, f"run_{run+1}")
                os.makedirs(run_folder, exist_ok=True)
                log_file = os.path.join(run_folder, "print.md")
                print(Fore.GREEN + f"Saving run {run+1}/{number} to: {log_file}")
                
                log_message(f"# Run {run+1}", log_file)
                log_message(f"# Function and Args", log_file)
                log_message(f"- Function: {func.__name__}", log_file)
                log_message(f"- Arguments: {args}", log_file)
                log_message(f"- Keyword Arguments: {kwargs}", log_file)
                
                # Lists to store monitoring data for this run.
                monitor_times = []         # Time in seconds
                busy_percentages = []      # CPU busy percentage
                memory_usages = []         # Memory usage delta (current - initial)
                battery_percentages = [] if BATTERY else None
                network_sent = []
                network_received = []
                
                process = psutil.Process()
                start_time = time.perf_counter()
                stop_monitoring = threading.Event()
                
                def monitor():
                    monitor_start = time.perf_counter()
                    mem_before = process.memory_info().rss  # in bytes

                    if BATTERY:
                        battery_sensor = psutil.sensors_battery()
                        battery_before = battery_sensor.percent if battery_sensor is not None else None
                    
                    while not stop_monitoring.is_set():
                        cpu_times = psutil.cpu_times_percent(interval=STEP_SECOND)

                        current_time = time.perf_counter() - monitor_start
                        current_memory = process.memory_info().rss - mem_before
                        busy = 100 - cpu_times.idle

                        monitor_times.append(current_time)
                        busy_percentages.append(busy)
                        memory_usages.append(current_memory)

                        if BATTERY and battery_before is not None:
                            current_battery = psutil.sensors_battery().percent
                            battery_percentages.append(current_battery)
                        
                        network_sent.append(network_bytes_sent)
                        network_received.append(network_bytes_received)
                
                # Start monitoring in a separate thread.
                monitor_thread = threading.Thread(target=monitor, daemon=True)
                monitor_thread.start()
                
                # Execute the target function.
                result = func(*args, **kwargs)
                last_result = result
                
                stop_monitoring.set()
                monitor_thread.join()
                end_time = time.perf_counter()
                execution_time = end_time - start_time
                all_execution_times.append(execution_time)
                
                # Compute memory usage metrics.
                avg_memory_used = np.mean(memory_usages) if memory_usages else 0
                max_memory_used = max(memory_usages) if memory_usages else 0
                min_memory_used = min(memory_usages) if memory_usages else 0
                all_avg_memory_used.append(avg_memory_used)
                all_max_memory_used.append(max_memory_used)
                all_min_memory_used.append(min_memory_used)
                
                # Compute CPU busy percentage metrics.
                avg_cpu_busy = np.mean(busy_percentages) if busy_percentages else 0
                max_cpu_busy = max(busy_percentages) if busy_percentages else 0
                min_cpu_busy = min(busy_percentages) if busy_percentages else 0
                all_avg_cpu_busy.append(avg_cpu_busy)
                all_max_cpu_busy.append(max_cpu_busy)
                all_min_cpu_busy.append(min_cpu_busy)
                
                # Log individual run results.
                log_message(f"# Profiling Results for Run {run+1}", log_file)
                log_message(f"## Execution Time", log_file)
                log_message(f"- Execution Time: {execution_time:.6f} seconds", log_file)
                log_message(f"## Additional Memory Usage", log_file)
                log_message(f"- Average Memory Usage: {format_bytes(avg_memory_used)}", log_file)
                log_message(f"- Max Memory Usage: {format_bytes(max_memory_used)}", log_file)
                log_message(f"- Min Memory Usage: {format_bytes(min_memory_used)}", log_file)
                log_message(f"## CPU Busy Percentage", log_file)
                log_message(f"- Average CPU Busy Percentage: {avg_cpu_busy:.2f}%", log_file)
                log_message(f"- Max CPU Busy Percentage: {max_cpu_busy:.2f}%", log_file)
                log_message(f"- Min CPU Busy Percentage: {min_cpu_busy:.2f}%", log_file)
                
                if BATTERY and battery_percentages:
                    avg_battery = np.mean(battery_percentages)
                    max_battery = max(battery_percentages)
                    min_battery = min(battery_percentages)
                    all_avg_battery.append(avg_battery)
                    all_max_battery.append(max_battery)
                    all_min_battery.append(min_battery)
                    log_message(f"## Battery Percentage", log_file)
                    log_message(f"- Average Battery Percentage: {avg_battery:.2f}%", log_file)
                    log_message(f"- Max Battery Percentage: {max_battery:.2f}%", log_file)
                    log_message(f"- Min Battery Percentage: {min_battery:.2f}%", log_file)
                
                final_sent = network_sent[-1] if network_sent else 0
                final_received = network_received[-1] if network_received else 0
                all_final_sent.append(final_sent)
                all_final_received.append(final_received)
                log_message(f"## Network Metrics", log_file)
                log_message(f"- Total Bytes Sent: {format_bytes(final_sent)}", log_file)
                log_message(f"- Total Bytes Received: {format_bytes(final_received)}", log_file)
                
                # Plot graphs for this run.
                plot_graph(monitor_times, [busy_percentages],
                           "Time (seconds)", ["CPU Busy Percentage"],
                           "CPU Busy Percentage Over Time", ['tab:red'], "graph_cpu.png", run_folder)
                plot_graph(monitor_times, [memory_usages],
                           "Time (seconds)", ["Memory Usage (bytes)"],
                           "Memory Usage Over Time", ['tab:blue'], "graph_ram.png", run_folder)
                if BATTERY and battery_percentages:
                    plot_graph(monitor_times, [battery_percentages],
                           "Time (seconds)", ["Battery Percentage"],
                           "Battery Percentage Over Time", ['tab:green'], "graph_battery.png", run_folder)
                
                plot_graph(monitor_times, [network_sent],
                        "Time (seconds)", ["Network Bytes Sent"],
                        "Network Bytes Over Time", ['tab:pink'], "graph_network_sent.png", run_folder)
                plot_graph(monitor_times, [network_received],
                        "Time (seconds)", ["Network Bytes Received"],
                        "Network Bytes Over Time", ['tab:purple'], "graph_network_received.png", run_folder)
                
                log_message(f"# Algorithm Result for Run {run+1}", log_file)
                log_message(f"- Result: {result}", log_file)

                # Save run time-series data for aggregated average graphs.
                aggregated_monitor_times.append(monitor_times)
                aggregated_busy_percentages.append(busy_percentages)
                aggregated_memory_usages.append(memory_usages)
                if BATTERY:
                    aggregated_battery_percentages.append(battery_percentages)
                
                aggregated_network_sent.append(network_sent)
                aggregated_network_received.append(network_received)
                
                # Collect garbage to avoid faking memory usage
                gc.collect()
            
            # If multiple runs were performed, compute and log aggregated results.
            if number > 1:
                aggregated_log = os.path.join(main_folder, "aggregated.md")
                print(Fore.GREEN + f"Saving aggregated results to: {aggregated_log}")
                
                log_message("# Aggregated Profiling Results", aggregated_log)
                # Execution Time aggregation
                agg_execution_time_avg = np.mean(all_execution_times)
                agg_execution_time_min = min(all_execution_times)
                agg_execution_time_max = max(all_execution_times)
                log_message("## Execution Time", aggregated_log)
                log_message(f"- Average Execution Time: {agg_execution_time_avg:.6f} seconds", aggregated_log)
                log_message(f"- Min Execution Time: {agg_execution_time_min:.6f} seconds", aggregated_log)
                log_message(f"- Max Execution Time: {agg_execution_time_max:.6f} seconds", aggregated_log)
                
                # Memory Usage aggregation
                agg_avg_memory = np.mean(all_avg_memory_used)
                agg_min_memory = min(all_min_memory_used)
                agg_max_memory = max(all_max_memory_used)
                log_message("## Additional Memory Usage", aggregated_log)
                log_message(f"- Average Memory Usage (avg of avgs): {format_bytes(agg_avg_memory)}", aggregated_log)
                log_message(f"- Min Memory Usage (min of mins): {format_bytes(agg_min_memory)}", aggregated_log)
                log_message(f"- Max Memory Usage (max of maxs): {format_bytes(agg_max_memory)}", aggregated_log)
                
                # CPU Busy Percentage aggregation
                agg_avg_cpu = np.mean(all_avg_cpu_busy)
                agg_min_cpu = min(all_min_cpu_busy)
                agg_max_cpu = max(all_max_cpu_busy)
                log_message("## CPU Busy Percentage", aggregated_log)
                log_message(f"- Average CPU Busy Percentage (avg of avgs): {agg_avg_cpu:.2f}%", aggregated_log)
                log_message(f"- Min CPU Busy Percentage (min of mins): {agg_min_cpu:.2f}%", aggregated_log)
                log_message(f"- Max CPU Busy Percentage (max of maxs): {agg_max_cpu:.2f}%", aggregated_log)
                
                if BATTERY:
                    agg_avg_batt = np.mean(all_avg_battery) if all_avg_battery else 0
                    agg_min_batt = min(all_min_battery) if all_min_battery else 0
                    agg_max_batt = max(all_max_battery) if all_max_battery else 0
                    log_message("## Battery Percentage", aggregated_log)
                    log_message(f"- Average Battery Percentage (avg of avgs): {agg_avg_batt:.2f}%", aggregated_log)
                    log_message(f"- Min Battery Percentage (min of mins): {agg_min_batt:.2f}%", aggregated_log)
                    log_message(f"- Max Battery Percentage (max of maxs): {agg_max_batt:.2f}%", aggregated_log)
                
                agg_final_sent_avg = np.mean(all_final_sent)
                agg_final_sent_min = min(all_final_sent)
                agg_final_sent_max = max(all_final_sent)
                agg_final_received_avg = np.mean(all_final_received)
                agg_final_received_min = min(all_final_received)
                agg_final_received_max = max(all_final_received)
                log_message("## Network Metrics", aggregated_log)
                log_message(f"- Total Bytes Sent (avg): {format_bytes(agg_final_sent_avg)}", aggregated_log)
                log_message(f"- Total Bytes Sent (min): {format_bytes(agg_final_sent_min)}", aggregated_log)
                log_message(f"- Total Bytes Sent (max): {format_bytes(agg_final_sent_max)}", aggregated_log)
                log_message(f"- Total Bytes Received (avg): {format_bytes(agg_final_received_avg)}", aggregated_log)
                log_message(f"- Total Bytes Received (min): {format_bytes(agg_final_received_min)}", aggregated_log)
                log_message(f"- Total Bytes Received (max): {format_bytes(agg_final_received_max)}", aggregated_log)
                
                # Compute and plot averaged time-series graphs on % time scale.
                if aggregated_monitor_times:
                    num_points = 100  # resolution for percentage scale
                    x_perc = np.linspace(0, 100, num=num_points)
                    busy_interp_all = []
                    memory_interp_all = []
                    network_sent_interp_all = []
                    network_received_interp_all = []
                    
                    # Interpolate each run's data onto the common percentage scale.
                    for times, busy, memory, net_sent, net_received in zip(
                        aggregated_monitor_times,
                        aggregated_busy_percentages,
                        aggregated_memory_usages,
                        aggregated_network_sent,
                        aggregated_network_received
                    ):
                        times = np.array(times)
                        norm_time = (times / times[-1]) * 100  # normalize time to percentage
                        busy_interp = np.interp(x_perc, norm_time, busy)
                        memory_interp = np.interp(x_perc, norm_time, memory)
                        net_sent_interp = np.interp(x_perc, norm_time, net_sent)
                        net_received_interp = np.interp(x_perc, norm_time, net_received)
                        busy_interp_all.append(busy_interp)
                        memory_interp_all.append(memory_interp)
                        network_sent_interp_all.append(net_sent_interp)
                        network_received_interp_all.append(net_received_interp)
                    
                    avg_busy = np.mean(busy_interp_all, axis=0)
                    avg_memory = np.mean(memory_interp_all, axis=0)
                    avg_network_sent = np.mean(network_sent_interp_all, axis=0)
                    avg_network_received = np.mean(network_received_interp_all, axis=0)
                    
                    plot_graph(x_perc, [avg_busy],
                           "Time (%)", ["Average CPU Busy Percentage"],
                           "Average CPU Busy Percentage Over % Time", ['tab:red'], "graph_avg_cpu.png", main_folder)
                    plot_graph(x_perc, [avg_memory],
                           "Time (%)", ["Average Memory Usage (bytes)"],
                           "Average Memory Usage Over % Time", ['tab:blue'], "graph_avg_ram.png", main_folder)
                    
                    if BATTERY and aggregated_battery_percentages:
                        battery_interp_all = []
                        for times, batt in zip(aggregated_monitor_times, aggregated_battery_percentages):
                            times = np.array(times)
                            norm_time = (times / times[-1]) * 100
                            batt_interp = np.interp(x_perc, norm_time, batt)
                            battery_interp_all.append(batt_interp)
                        avg_battery = np.mean(battery_interp_all, axis=0)
                        plot_graph(x_perc, [avg_battery],
                           "Time (%)", ["Average Battery Percentage"],
                           "Average Battery Percentage Over % Time", ['tab:green'], "graph_avg_battery.png", main_folder)
                    
                    plot_graph(x_perc, [avg_network_sent],
                        "Time (%)", ["Average Network Bytes Sent"],
                        "Average Network Bytes Sent Over % Time", ['tab:pink'], "graph_avg_network_sent.png", main_folder)
                    plot_graph(x_perc, [avg_network_received],
                        "Time (%)", ["Average Network Bytes Received"],
                        "Average Network Bytes Received Over % Time", ['tab:purple'], "graph_avg_network_received.png", main_folder)
            
            return last_result
        return wrapper
    return decorator

# Example usage with pyRAPL commented out.
#@pyRAPL.measureit
@profile_and_monitor(number=2)
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
    print(Fore.BLUE + "Algorithm result:", result)
