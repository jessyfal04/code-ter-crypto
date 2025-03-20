import os
import time
import threading
import psutil
import functools
import gc
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from colorama import Fore
import pyRAPL.pyRAPL

STEP_SECOND = 0.5  # Sampling interval in seconds
NUM_POINTS = 20    # Number of points for interpolation
PLOT_PRINT = False  # Set to True to show plots
BATTERY = False     # Set to True to enable battery monitoring
if BATTERY:
    pyRAPL.setup()

current_network_bytes_sent = 0     # Global variable for network bytes sent
current_network_bytes_received = 0   # Global variable for network bytes received
current_run = 0

# --- Metrics Classes ---

class MetricsRun:
    """
    Stores time series data for a single metric.
    Attributes:
      - name: The name for graph labeling.
      - color: Color to be used in plotting.
      - graph_filename: The filename to save the graph (e.g., "graph_cpu.png").
      - graph_title: The title for the graph (e.g., "CPU Busy Percentage Over Time").
      - times: List of time stamps.
      - values: List of metric values recorded at corresponding times.
    """
    def __init__(self, name, color, graph_filename="", graph_title=""):
        self.name = name
        self.color = color
        self.graph_filename = graph_filename
        self.graph_title = graph_title
        self.times = []
        self.values = []
    
    def add_measurement(self, t, value):
        self.times.append(t)
        self.values.append(value)
    
    def get_avg(self):
        return np.mean(self.values)
    
    def get_min(self):
        return min(self.values)
    
    def get_max(self):
        return max(self.values)
    
    def get_sum(self):
        return sum(self.values)

class MetricsAggregated:
    """
    Aggregates multiple MetricsRun objects (from different runs)
    for the same metric, and computes overall min, max, average,
    as well as an averaged time series. If each run contains a single measurement,
    the run index is used as the x-axis.
    
    Attributes:
      - graph_filename: The filename to save the aggregated graph.
      - graph_title: The title for the aggregated graph.
    """
    def __init__(self, name:str, color:str, graph_filename:str="", graph_title:str=""):
        self.name = name
        self.color = color
        self.graph_filename = graph_filename
        self.graph_title = graph_title
        self.runs = []

    def add_metric_run(self, run : MetricsRun):
        self.runs.append(run)
    
    def aggregated_avg(self):
        return np.mean([run.get_avg() for run in self.runs])
    
    def aggregated_min(self):
        return min([run.get_min() for run in self.runs])
    
    def aggregated_max(self):
        return max([run.get_max() for run in self.runs])
    
    def aggregated_avg_of_sum(self):
        return np.mean([run.get_sum() for run in self.runs])
    
    def get_average_series(self):
        # If each run has exactly one measurement, use the run index for x-axis.
        if all(len(run.times) == 1 for run in self.runs if run.times):
            x_data = np.arange(1, len(self.runs) + 1)
            y_data = np.array([run.values[0] for run in self.runs])
            return x_data, y_data
        # Otherwise, interpolate each run's data onto a common percentage scale.
        x_perc = np.linspace(0, 100, num=NUM_POINTS)
        series_list = []
        for run in self.runs:
            if run.times and run.times[-1] > 0:
                times = np.array(run.times)
                norm_time = (times / times[-1]) * 100  # Normalize to percentage scale
                interp_values = np.interp(x_perc, norm_time, run.values)
                series_list.append(interp_values)
        if series_list:
            avg_series = np.mean(series_list, axis=0)
        else:
            avg_series = np.zeros_like(x_perc)
        return x_perc, avg_series

# --- Utility Functions ---

def plot_graph(x_data, y_data, title, y_label, filename, folder, x_label="Time (seconds)", color=None):
    """
    Simplified plotting: always one x-label and one y-label.
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.plot(x_data, y_data, label=y_label, color=color if color else "blue")
    ax.legend()
    plt.title(title)
    fig.tight_layout()
    file_path = os.path.join(folder, f"{filename}")
    fig.savefig(file_path)
    print(Fore.GREEN + f"Saving graph '{title}' to: {file_path}")
    if PLOT_PRINT:
        plt.show()

def plot_metric(metric, folder : str, isAggregated:bool=False):
    """
    Merged plotting function for both run and aggregated metrics.
    When isAggregated is True, it uses metric.get_average_series and sets x_label to "Time (%)".
    Otherwise, it uses the raw metric.times and metric.values with x_label "Time (seconds)".
    It also uses the graph_title and graph_filename from the metric instance.
    """
    if isAggregated:
        x_data, y_data = metric.get_average_series()
        x_label = "Time (%)"
    else:
        x_data, y_data = metric.times, metric.values
        x_label = "Time (seconds)"
    title = metric.graph_title if metric.graph_title else f"{metric.name} Graph"
    filename = metric.graph_filename if metric.graph_filename else "graph.png"
    plot_graph(x_data, y_data, title, metric.name, filename, folder, x_label=x_label, color=metric.color)

def log_message(message : str, log_file : str):
    with open(log_file, "a") as f:
        f.write(message + "\n")
    if PLOT_PRINT:
        print(Fore.GREEN + message)

def format_bytes(num_bytes : int):
    """
    Format bytes to a human-readable string.
    Always stop at TB if the value is huge.
    """
    sign = "-" if num_bytes < 0 else ""
    num = abs(num_bytes)
    units = ['bytes', 'KB', 'MB', 'GB', 'TB']
    for i, unit in enumerate(units):
        if i == len(units) - 1:  # Always return TB for huge values
            return f"{sign}{num:.2f} {unit}"
        if num < 1024:
            return f"{sign}{num:.2f} {unit}"
        num /= 1024

# --- Decorator for Profiling and Monitoring ---

def profile_and_monitor(number : int=1, annotation : str=""):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            main_folder = f"results_profile/{func.__name__}_{timestamp}"
            os.makedirs(main_folder, exist_ok=True)
            
            # Create aggregated metric objects.
            exec_time_agg = MetricsAggregated("Execution Time", 'tab:green', graph_filename="graph_avg_execution_time.png", graph_title="Execution Time Per Run")
            cpu_agg = MetricsAggregated("CPU Busy Percentage", 'tab:red', graph_filename="graph_avg_cpu.png", graph_title="Average CPU Busy Percentage Over % Time")
            memory_agg = MetricsAggregated("Memory Usage (bytes)", 'tab:blue', graph_filename="graph_avg_ram.png", graph_title="Average Memory Usage Over % Time")
            net_sent_agg = MetricsAggregated("Network Bytes Sent", 'tab:pink', graph_filename="graph_avg_network_sent.png", graph_title="Average Network Bytes Sent Over % Time")
            net_recv_agg = MetricsAggregated("Network Bytes Received", 'tab:purple', graph_filename="graph_avg_network_received.png", graph_title="Average Network Bytes Received Over % Time")
            if BATTERY:
                battery_agg = MetricsAggregated("Battery Consumption (Joules)", 'tab:orange', graph_filename="graph_avg_battery.png", graph_title="Average Battery Consumption Over % Time")
            
            result = None
            
            for run in range(number):
                global current_run, current_network_bytes_sent, current_network_bytes_received
                current_run = run

                # Create a folder for each run and log the function and arguments.
                run_folder = os.path.join(main_folder, f"run_{run+1}")
                os.makedirs(run_folder, exist_ok=True)
                log_file = os.path.join(run_folder, "print.md")
                print(Fore.GREEN + f"Saving run {run+1}/{number} to: {log_file}")
                
                log_message(f"# Run {run+1}", log_file)
                log_message("## Function and Args", log_file)
                log_message(f"- Function: {func.__name__}", log_file)
                #log_message(f"- Arguments: {args}", log_file)
                #log_message(f"- Keyword Arguments: {kwargs}", log_file)
                log_message(f"- Annotation: {annotation}", log_file)
                print(Fore.WHITE)

                # Initialize MetricsRun objects for this run.
                exec_metric = MetricsRun("Execution Time", 'tab:green', graph_filename="graph_execution_time.png", graph_title="Execution Time Per Run")
                cpu_metric = MetricsRun("CPU Busy Percentage", 'tab:red', graph_filename="graph_cpu.png", graph_title="CPU Busy Percentage Over Time")
                memory_metric = MetricsRun("Memory Usage (bytes)", 'tab:blue', graph_filename="graph_ram.png", graph_title="Memory Usage Over Time")
                network_sent_metric = MetricsRun("Network Bytes Sent", 'tab:pink', graph_filename="graph_network_sent.png", graph_title="Network Bytes Sent Over Time")
                network_received_metric = MetricsRun("Network Bytes Received", 'tab:purple', graph_filename="graph_network_received.png", graph_title="Network Bytes Received Over Time")
                if BATTERY:
                    battery_metric = MetricsRun("Battery Consumption (Joules)", 'tab:orange', graph_filename="graph_battery.png", graph_title="Battery Consumption Over Time")
                
                psutil_process = psutil.Process()
                stop_monitoring = threading.Event()
                
                def monitor():
                    global current_network_bytes_sent, current_network_bytes_received
                    monitor_time_start = time.perf_counter()
                    memory_before = psutil_process.memory_info().rss
                    current_network_bytes_sent = 0
                    current_network_bytes_received = 0

                    while not stop_monitoring.is_set():
                        monitor_time_current = time.perf_counter() - monitor_time_start

                        if BATTERY:
                            battery_meter = pyRAPL.Measurement('bar')
                            battery_meter.begin()
                        
                        cpu_times = psutil.cpu_times_percent(interval=STEP_SECOND)

                        if BATTERY:
                            battery_meter.end()
                            battery_metric.add_measurement(monitor_time_current, battery_meter.result.pkg[0])

                        cpu_metric.add_measurement(monitor_time_current, 100 - cpu_times.idle)
                        memory_metric.add_measurement(monitor_time_current, psutil_process.memory_info().rss - memory_before)
                        network_sent_metric.add_measurement(monitor_time_current, current_network_bytes_sent)
                        network_received_metric.add_measurement(monitor_time_current, current_network_bytes_received)                            
                
                monitor_thread = threading.Thread(target=monitor, daemon=True)
                monitor_thread.start()
                
                func_time_start = time.perf_counter()
                result = func(*args, **kwargs)
                func_time_end = time.perf_counter()
                
                stop_monitoring.set()
                monitor_thread.join()

                # Compute execution time.
                func_time_execution = func_time_end - func_time_start
                exec_metric.add_measurement(1, func_time_execution)
                
                # Log run results.
                log_message("## Profiling Results", log_file)
                log_message("### Execution Time", log_file)
                log_message(f"- Execution Time: {func_time_execution:.6f} seconds", log_file)

                log_message("### Additional Memory Usage", log_file)
                log_message(f"- Average Memory Usage: {format_bytes(memory_metric.get_avg())}", log_file)
                log_message(f"- Max Memory Usage: {format_bytes(memory_metric.get_max())}", log_file)
                log_message(f"- Min Memory Usage: {format_bytes(memory_metric.get_min())}", log_file)
                
                log_message("### CPU Busy Percentage", log_file)
                log_message(f"- Average CPU Busy: {cpu_metric.get_avg():.2f}%", log_file)
                log_message(f"- Max CPU Busy: {cpu_metric.get_max():.2f}%", log_file)
                log_message(f"- Min CPU Busy: {cpu_metric.get_min():.2f}%", log_file)
                
                log_message("### Network Metrics", log_file)
                log_message(f"- Total Bytes Sent: {format_bytes(current_network_bytes_sent)}", log_file)
                log_message(f"- Total Bytes Received: {format_bytes(current_network_bytes_received)}", log_file)
                
                if BATTERY:
                    log_message("### Battery Consumption", log_file)
                    log_message(f"- Total Battery Consumption: {battery_metric.get_sum():.6f} Joules", log_file)
                
                # Plotting for this run using the merged plot_metric function.
                plot_metric(cpu_metric, run_folder, isAggregated=False)
                plot_metric(memory_metric, run_folder, isAggregated=False)
                plot_metric(network_sent_metric, run_folder, isAggregated=False)
                plot_metric(network_received_metric, run_folder, isAggregated=False)
                if BATTERY:
                    plot_metric(battery_metric, run_folder, isAggregated=False)
                
                log_message("# Algorithm Result", log_file)
                log_message(f"- Result: {result}", log_file)
                
                # Add each run's metrics to the aggregated objects.
                exec_time_agg.add_metric_run(exec_metric)
                cpu_agg.add_metric_run(cpu_metric)
                memory_agg.add_metric_run(memory_metric)
                net_sent_agg.add_metric_run(network_sent_metric)
                net_recv_agg.add_metric_run(network_received_metric)
                if BATTERY:
                    battery_agg.add_metric_run(battery_metric)
                
                gc.collect()
            
            # Compute aggregated results if multiple runs were performed.
            if number > 1:
                aggregated_log = os.path.join(main_folder, "aggregated.md")
                print(Fore.GREEN + f"Saving aggregated results to: {aggregated_log}")
                log_message("# Aggregated Profiling Results", aggregated_log)
                log_message("## Function and Args", aggregated_log)
                log_message(f"- Function: {func.__name__}", aggregated_log)
                #log_message(f"- Arguments: {args}", aggregated_log)
                #log_message(f"- Keyword Arguments: {kwargs}", aggregated_log)
                log_message(f"- Annotation: {annotation}", aggregated_log)
                
                # Log aggregated execution time metric.
                log_message("### Execution Time", aggregated_log)
                log_message(f"- Average: {exec_time_agg.aggregated_avg():.6f} seconds", aggregated_log)
                log_message(f"- Min: {exec_time_agg.aggregated_min():.6f} seconds", aggregated_log)
                log_message(f"- Max: {exec_time_agg.aggregated_max():.6f} seconds", aggregated_log)
                
                # Aggregate Memory and CPU using MetricsAggregated.
                log_message("### Additional Memory Usage", aggregated_log)
                log_message(f"- Average (avg of avgs): {format_bytes(memory_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min (min of mins): {format_bytes(memory_agg.aggregated_min())}", aggregated_log)
                log_message(f"- Max (max of maxs): {format_bytes(memory_agg.aggregated_max())}", aggregated_log)
                
                log_message("### CPU Busy Percentage", aggregated_log)
                log_message(f"- Average (avg of avgs): {cpu_agg.aggregated_avg():.2f}%", aggregated_log)
                log_message(f"- Min (min of mins): {cpu_agg.aggregated_min():.2f}%", aggregated_log)
                log_message(f"- Max (max of maxs): {cpu_agg.aggregated_max():.2f}%", aggregated_log)
                
                # Aggregate Network metrics.
                log_message("### Network Metrics", aggregated_log)
                log_message(f"- Total Bytes Sent (avg): {format_bytes(net_sent_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Total Bytes Sent (min): {format_bytes(net_sent_agg.aggregated_min())}", aggregated_log)
                log_message(f"- Total Bytes Sent (max): {format_bytes(net_sent_agg.aggregated_max())}", aggregated_log)
                log_message(f"- Total Bytes Received (avg): {format_bytes(net_recv_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Total Bytes Received (min): {format_bytes(net_recv_agg.aggregated_min())}", aggregated_log)
                log_message(f"- Total Bytes Received (max): {format_bytes(net_recv_agg.aggregated_max())}", aggregated_log)
                
                if BATTERY:
                    log_message("### Battery Consumption", aggregated_log)
                    log_message(f"- Average Battery Consumption: {battery_agg.aggregated_avg_of_sum():.6f} Joules", aggregated_log)
                
                # Plot aggregated time series graphs using the merged plot_metric function.
                plot_metric(cpu_agg, main_folder, isAggregated=True)
                plot_metric(memory_agg, main_folder, isAggregated=True)
                plot_metric(net_sent_agg, main_folder, isAggregated=True)
                plot_metric(net_recv_agg, main_folder, isAggregated=True)
                #plot_metric(exec_time_agg, main_folder, isAggregated=True)
                if BATTERY:
                    plot_metric(battery_agg, main_folder, isAggregated=True)
            
            return result
        return wrapper
    return decorator

# --- Example Function ---

@profile_and_monitor(number=2)
def dummy(range_mod=2**24, modulo=7, range_sum=2**8):
    """
    Dummy heavy function simulating intensive computation and additional memory allocation.
    """
    gc.collect()
    totalMod = 0
    totalSum = 0

    # Modulo computation.
    extra_memory = [i for i in range(range_mod)]
    for value in extra_memory:
        totalMod += value % modulo
    del extra_memory
    gc.collect()

    # Sum computation.
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
    print(Fore.WHITE)
