import os
import time
import threading
import psutil
import functools
import gc
import matplotlib
matplotlib.use('Agg')  # Set backend to non-interactive
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from colorama import Fore
import pyRAPL.pyRAPL

STEP_SECOND = 0.1  # Sampling interval in seconds
NUM_POINTS = 20    # Number of points for interpolation
PLOT_PRINT = False  # Set to True to show plots
BATTERY = False     # Set to True to enable battery monitoring
if BATTERY:
    pyRAPL.setup()

current_network_bytes_sent = 0     # Global variable for network bytes sent
current_network_bytes_received = 0   # Global variable for network bytes received
current_network_latency = 0         # Global variable for network latency

# Global variables for phase timestamps
encrypt_start_time = 0     # Start time of encryption phase
encrypt_end_time = 0       # End time of encryption phase
operation_start_time = 0   # Start time of operation phase
operation_end_time = 0     # End time of operation phase
decrypt_start_time = 0     # Start time of decryption phase
decrypt_end_time = 0       # End time of decryption phase

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
    
    def aggregated_min_of_avg(self):
        return min([run.get_avg() for run in self.runs])
    
    def aggregated_max_of_avg(self):
        return max([run.get_avg() for run in self.runs])

    
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

class PhaseMetrics:
    """
    Stores phase timing information for a single run.
    """
    def __init__(self):
        self.encrypt_duration = 0
        self.operation_duration = 0
        self.decrypt_duration = 0
        self.encrypt_start = 0
        self.encrypt_end = 0
        self.operation_start = 0
        self.operation_end = 0
        self.decrypt_start = 0
        self.decrypt_end = 0
        self.total_duration = 0

    def update_from_globals(self, run_start_time, run_end_time):
        global encrypt_start_time, encrypt_end_time, operation_start_time, operation_end_time, decrypt_start_time, decrypt_end_time

        # Convert absolute timestamps to relative timestamps from run start
        self.encrypt_start = encrypt_start_time - run_start_time if encrypt_start_time != 0 else 0
        self.encrypt_end = encrypt_end_time - run_start_time if encrypt_end_time != 0 else 0
        self.operation_start = operation_start_time - run_start_time if operation_start_time != 0 else 0
        self.operation_end = operation_end_time - run_start_time if operation_end_time != 0 else 0
        self.decrypt_start = decrypt_start_time - run_start_time if decrypt_start_time != 0 else 0
        self.decrypt_end = decrypt_end_time - run_start_time if decrypt_end_time != 0 else 0
        self.total_duration = run_end_time - run_start_time
        
        if self.encrypt_start != 0 and self.encrypt_end != 0:
            self.encrypt_duration = self.encrypt_end - self.encrypt_start
        if self.operation_start != 0 and self.operation_end != 0:
            self.operation_duration = self.operation_end - self.operation_start
        if self.decrypt_start != 0 and self.decrypt_end != 0:
            self.decrypt_duration = self.decrypt_end - self.decrypt_start

    def get_percentage_timestamps(self):
        """Convert timestamps to percentages of total duration"""
        if self.total_duration == 0:
            return self
        
        result = PhaseMetrics()
        result.total_duration = self.total_duration
        
        if self.encrypt_start != 0:
            result.encrypt_start = (self.encrypt_start / self.total_duration) * 100
        if self.encrypt_end != 0:
            result.encrypt_end = (self.encrypt_end / self.total_duration) * 100
        if self.operation_start != 0:
            result.operation_start = (self.operation_start / self.total_duration) * 100
        if self.operation_end != 0:
            result.operation_end = (self.operation_end / self.total_duration) * 100
        if self.decrypt_start != 0:
            result.decrypt_start = (self.decrypt_start / self.total_duration) * 100
        if self.decrypt_end != 0:
            result.decrypt_end = (self.decrypt_end / self.total_duration) * 100
            
        return result

class PhaseMetricsAggregated:
    """
    Aggregates phase metrics across multiple runs.
    """
    def __init__(self):
        self.runs = []

    def add_phase_metrics(self, metrics: PhaseMetrics):
        self.runs.append(metrics)

    def get_avg_encrypt_duration(self):
        return np.mean([run.encrypt_duration for run in self.runs if run.encrypt_duration > 0])

    def get_avg_operation_duration(self):
        return np.mean([run.operation_duration for run in self.runs if run.operation_duration > 0])

    def get_avg_decrypt_duration(self):
        return np.mean([run.decrypt_duration for run in self.runs if run.decrypt_duration > 0])
    
    def get_min_encrypt_duration(self):
        return min([run.encrypt_duration for run in self.runs if run.encrypt_duration > 0])

    def get_min_operation_duration(self):
        return min([run.operation_duration for run in self.runs if run.operation_duration > 0])

    def get_min_decrypt_duration(self):
        return min([run.decrypt_duration for run in self.runs if run.decrypt_duration > 0])
    
    def get_max_encrypt_duration(self):
        return max([run.encrypt_duration for run in self.runs if run.encrypt_duration > 0])

    def get_max_operation_duration(self):
        return max([run.operation_duration for run in self.runs if run.operation_duration > 0])
    
    def get_max_decrypt_duration(self):
        return max([run.decrypt_duration for run in self.runs if run.decrypt_duration > 0])

    def get_average_phase_metrics(self):
        """Get average phase metrics with timestamps interpolated to percentage scale using NUM_POINTS"""
        if not self.runs:
            return None
            
        # Convert each run's timestamps to percentages
        percentage_runs = [run.get_percentage_timestamps() for run in self.runs]
        
        # Create a result metrics object
        result = PhaseMetrics()
        result.total_duration = 100  # 100%
        
        # Create x-axis points for interpolation
        x_perc = np.linspace(0, 100, num=NUM_POINTS)
        
        # Interpolate each phase's start and end times
        def interpolate_phase_times(times):
            if not times:
                return None
            # Filter out zero values and get valid times
            valid_times = [t for t in times if t != 0]
            if not valid_times:
                return None
            # Interpolate to NUM_POINTS points
            return np.interp(x_perc, np.linspace(0, 100, len(valid_times)), valid_times)
        
        # Interpolate each phase's timestamps
        encrypt_starts = [run.encrypt_start for run in percentage_runs if run.encrypt_start != 0]
        encrypt_ends = [run.encrypt_end for run in percentage_runs if run.encrypt_end != 0]
        operation_starts = [run.operation_start for run in percentage_runs if run.operation_start != 0]
        operation_ends = [run.operation_end for run in percentage_runs if run.operation_end != 0]
        decrypt_starts = [run.decrypt_start for run in percentage_runs if run.decrypt_start != 0]
        decrypt_ends = [run.decrypt_end for run in percentage_runs if run.decrypt_end != 0]
        
        # Get interpolated values and take the average
        if encrypt_starts:
            result.encrypt_start = np.mean(interpolate_phase_times(encrypt_starts))
        if encrypt_ends:
            result.encrypt_end = np.mean(interpolate_phase_times(encrypt_ends))
        if operation_starts:
            result.operation_start = np.mean(interpolate_phase_times(operation_starts))
        if operation_ends:
            result.operation_end = np.mean(interpolate_phase_times(operation_ends))
        if decrypt_starts:
            result.decrypt_start = np.mean(interpolate_phase_times(decrypt_starts))
        if decrypt_ends:
            result.decrypt_end = np.mean(interpolate_phase_times(decrypt_ends))
            
        return result

# --- Utility Functions ---

def plot_graph(x_data, y_data, title, y_label, filename, folder, x_label="Time (seconds)", color=None, phase_metrics=None):
    """
    Enhanced plotting function that can add phase lines if phase_metrics is provided.
    """
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.plot(x_data, y_data, label=y_label, color=color if color else "blue")
    
    if phase_metrics:
        # Add phase lines if timestamps are non-zero
        if phase_metrics.encrypt_start != 0 and phase_metrics.encrypt_end != 0:
            ax.axvline(x=phase_metrics.encrypt_start, color='red', linestyle='--', label='Encrypt Start')
            ax.axvline(x=phase_metrics.encrypt_end, color='red', linestyle='-', label='Encrypt End')
        if phase_metrics.operation_start != 0 and phase_metrics.operation_end != 0:
            ax.axvline(x=phase_metrics.operation_start, color='green', linestyle='--', label='Operation Start')
            ax.axvline(x=phase_metrics.operation_end, color='green', linestyle='-', label='Operation End')
        if phase_metrics.decrypt_start != 0 and phase_metrics.decrypt_end != 0:
            ax.axvline(x=phase_metrics.decrypt_start, color='purple', linestyle='--', label='Decrypt Start')
            ax.axvline(x=phase_metrics.decrypt_end, color='purple', linestyle='-', label='Decrypt End')
    
    ax.legend()
    plt.title(title)
    fig.tight_layout()
    file_path = os.path.join(folder, f"{filename}")
    fig.savefig(file_path)
    plt.close(fig)  # Close the figure to free memory
    if PLOT_PRINT:
        plt.show()

def plot_metric(metric, folder : str, isAggregated:bool=False, phase_metrics=None, phase_agg=None):
    """
    Enhanced plotting function that can add phase lines.
    """
    if isAggregated:
        x_data, y_data = metric.get_average_series()
        x_label = "Time (%)"
        # For aggregated plots, use the average phase metrics with percentage timestamps
        if phase_agg:
            phase_metrics = phase_agg.get_average_phase_metrics()
    else:
        x_data, y_data = metric.times, metric.values
        x_label = "Time (seconds)"
    title = metric.graph_title if metric.graph_title else f"{metric.name} Graph"
    filename = metric.graph_filename if metric.graph_filename else "graph.png"
    plot_graph(x_data, y_data, title, metric.name, filename, folder, x_label=x_label, color=metric.color, phase_metrics=phase_metrics)

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

def profile_and_monitor(number : int=1, folder_prefix : str="", annotation : str=""):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            main_folder = f"results_profile/{folder_prefix}_{func.__name__}_{timestamp}"
            os.makedirs(main_folder, exist_ok=True)
            
            # Create aggregated metric objects.
            exec_time_agg = MetricsAggregated("Execution Time", 'tab:green', graph_filename="graph_avg_execution_time.png", graph_title="Execution Time Per Run")
            cpu_agg = MetricsAggregated("CPU Busy Percentage", 'tab:red', graph_filename="graph_avg_cpu.png", graph_title="Average CPU Busy Percentage Over % Time")
            memory_agg = MetricsAggregated("Memory Usage (bytes)", 'tab:blue', graph_filename="graph_avg_ram.png", graph_title="Average Memory Usage Over % Time")
            net_sent_agg = MetricsAggregated("Network Bytes Sent", 'tab:pink', graph_filename="graph_avg_network_sent.png", graph_title="Average Network Bytes Sent Over % Time")
            net_recv_agg = MetricsAggregated("Network Bytes Received", 'tab:purple', graph_filename="graph_avg_network_received.png", graph_title="Average Network Bytes Received Over % Time")
            net_latency_agg = MetricsAggregated("Network Latency (ms)", 'tab:cyan', graph_filename="graph_avg_network_latency.png", graph_title="Average Network Latency Over % Time")
            disk_read_agg = MetricsAggregated("Disk Read (bytes)", 'tab:gray', graph_filename="graph_avg_disk_read.png", graph_title="Average Disk Read Bytes Over % Time")
            disk_write_agg = MetricsAggregated("Disk Write (bytes)", 'tab:brown', graph_filename="graph_avg_disk_write.png", graph_title="Average Disk Write Bytes Over % Time")
            if BATTERY:
                battery_agg = MetricsAggregated("Battery Consumption (Joules)", 'tab:orange', graph_filename="graph_avg_battery.png", graph_title="Average Battery Consumption Over % Time")
            
            # Create aggregated phase metrics
            phase_agg = PhaseMetricsAggregated()
            
            result = None
            
            for run in range(number):
                global current_run, current_network_bytes_sent, current_network_bytes_received, current_network_latency
                global encrypt_start_time, encrypt_end_time, operation_start_time, operation_end_time, decrypt_start_time, decrypt_end_time
                current_run = run

                # Create a folder for each run and log the function and arguments.
                run_folder = os.path.join(main_folder, f"run_{run+1}")
                os.makedirs(run_folder, exist_ok=True)
                log_file = os.path.join(run_folder, "print.md")
                print(Fore.GREEN + f"Saving run {run+1}/{number} to: {log_file}")
                
                log_message(f"# Run {run+1}", log_file)
                log_message("## Function and Args", log_file)
                log_message(f"- Function: {func.__name__}", log_file)
                log_message(f"- Annotation: {annotation}", log_file)
                print(Fore.RESET)

                # Initialize MetricsRun objects for this run.
                exec_metric = MetricsRun("Execution Time", 'tab:green', graph_filename="graph_execution_time.png", graph_title="Execution Time Per Run")
                cpu_metric = MetricsRun("CPU Busy Percentage", 'tab:red', graph_filename="graph_cpu.png", graph_title="CPU Busy Percentage Over Time")
                memory_metric = MetricsRun("Memory Usage (bytes)", 'tab:blue', graph_filename="graph_ram.png", graph_title="Memory Usage Over Time")
                network_sent_metric = MetricsRun("Network Bytes Sent", 'tab:pink', graph_filename="graph_network_sent.png", graph_title="Network Bytes Sent Over Time")
                network_received_metric = MetricsRun("Network Bytes Received", 'tab:purple', graph_filename="graph_network_received.png", graph_title="Network Bytes Received Over Time")
                network_latency_metric = MetricsRun("Network Latency (ms)", 'tab:cyan', graph_filename="graph_network_latency.png", graph_title="Network Latency Over Time")
                disk_read_metric = MetricsRun("Disk Read (bytes)", 'tab:gray', graph_filename="graph_disk_read.png", graph_title="Disk Read Bytes Over Time")
                disk_write_metric = MetricsRun("Disk Write (bytes)", 'tab:brown', graph_filename="graph_disk_write.png", graph_title="Disk Write Bytes Over Time")
                if BATTERY:
                    battery_metric = MetricsRun("Battery Consumption (Joules)", 'tab:orange', graph_filename="graph_battery.png", graph_title="Battery Consumption Over Time")
                
                psutil_process = psutil.Process()
                stop_monitoring = threading.Event()
                
                def monitor():
                    global current_network_bytes_sent, current_network_bytes_received, current_network_latency
                    monitor_time_start = time.perf_counter()
                    memory_before = psutil_process.memory_info().rss
                    disk_io_before = psutil.disk_io_counters()

                    while not stop_monitoring.is_set():
                        monitor_time_current = time.perf_counter() - monitor_time_start

                        if BATTERY:
                            battery_meter = pyRAPL.Measurement('bar')
                            battery_meter.begin()
                        
                        cpu_times = psutil.cpu_times_percent(interval=STEP_SECOND)

                        if BATTERY:
                            battery_meter.end()
                            battery_metric.add_measurement(monitor_time_current, battery_meter.result.pkg[0])

                        disk_io_current = psutil.disk_io_counters()
                        disk_read_metric.add_measurement(monitor_time_current,  disk_io_current.read_bytes - disk_io_before.read_bytes)
                        disk_write_metric.add_measurement(monitor_time_current,  disk_io_current.write_bytes - disk_io_before.write_bytes)

                        cpu_metric.add_measurement(monitor_time_current, 100 - cpu_times.idle)
                        memory_metric.add_measurement(monitor_time_current, psutil_process.memory_info().rss - memory_before)
                        network_sent_metric.add_measurement(monitor_time_current, current_network_bytes_sent)
                        network_received_metric.add_measurement(monitor_time_current, current_network_bytes_received)
                        network_latency_metric.add_measurement(monitor_time_current, current_network_latency)     
                
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
                
                # Create and update phase metrics
                phase_metrics = PhaseMetrics()
                phase_metrics.update_from_globals(func_time_start, func_time_end)  # Pass both start and end times
                phase_agg.add_phase_metrics(phase_metrics)
                
                # Log run results.
                log_message("## Profiling Results", log_file)
                log_message("### Execution Time", log_file)
                log_message(f"- Execution Time: {func_time_execution:.6f} seconds", log_file)

                # Log phase durations
                log_message("### Phase Durations", log_file)
                if phase_metrics.encrypt_duration > 0:
                    log_message(f"- Encryption Duration: {phase_metrics.encrypt_duration:.6f} seconds", log_file)
                if phase_metrics.operation_duration > 0:
                    log_message(f"- Operation Duration: {phase_metrics.operation_duration:.6f} seconds", log_file)
                if phase_metrics.decrypt_duration > 0:
                    log_message(f"- Decryption Duration: {phase_metrics.decrypt_duration:.6f} seconds", log_file)

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
                log_message(f"- Total Network Latency: {current_network_latency:.6f} ms", log_file)

                log_message("### Disk I/O Metrics", log_file)
                log_message(f"- Total Disk Read: {format_bytes(disk_read_metric.get_sum())}", log_file)
                log_message(f"- Total Disk Write: {format_bytes(disk_write_metric.get_sum())}", log_file)

                if BATTERY:
                    log_message("### Battery Consumption", log_file)
                    log_message(f"- Total Battery Consumption: {battery_metric.get_sum():.6f} Joules", log_file)
                
                # Plotting for this run using the merged plot_metric function.
                plot_metric(cpu_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                plot_metric(memory_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                plot_metric(network_sent_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                plot_metric(network_received_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                plot_metric(disk_read_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                plot_metric(disk_write_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                if BATTERY:
                    plot_metric(battery_metric, run_folder, isAggregated=False, phase_metrics=phase_metrics)
                
                log_message("# Algorithm Result", log_file)
                log_message(f"- Result: {result}", log_file)
                
                # Add each run's metrics to the aggregated objects.
                exec_time_agg.add_metric_run(exec_metric)
                cpu_agg.add_metric_run(cpu_metric)
                memory_agg.add_metric_run(memory_metric)
                net_sent_agg.add_metric_run(network_sent_metric)
                net_recv_agg.add_metric_run(network_received_metric)
                net_latency_agg.add_metric_run(network_latency_metric)
                disk_read_agg.add_metric_run(disk_read_metric)
                disk_write_agg.add_metric_run(disk_write_metric)
                if BATTERY:
                    battery_agg.add_metric_run(battery_metric)
                
                gc.collect()
                print(Fore.GREEN + f"Run {run+1}/{number} completed.")
                print(Fore.RESET)

            
            # Compute aggregated results if multiple runs were performed.
            if number > 1:
                aggregated_log = os.path.join(main_folder, "aggregated.md")
                print(Fore.GREEN + f"Saving aggregated results to: {aggregated_log}")
                log_message("# Aggregated Profiling Results", aggregated_log)
                log_message("## Function and Args", aggregated_log)
                log_message(f"- Function: {func.__name__}", aggregated_log)
                log_message(f"- Annotation: {annotation}", aggregated_log)
                
                # Log aggregated execution time metric.
                log_message("### Execution Time", aggregated_log)
                log_message(f"- Average: {exec_time_agg.aggregated_avg():.6f} seconds", aggregated_log)
                log_message(f"- Min: {exec_time_agg.aggregated_min_of_avg():.6f} seconds", aggregated_log)
                log_message(f"- Max: {exec_time_agg.aggregated_max_of_avg():.6f} seconds", aggregated_log)
                
                # Log aggregated phase durations
                log_message("### Phase Durations", aggregated_log)
                
                if phase_agg.get_avg_encrypt_duration() > 0:
                    log_message(f"- Average Encryption Duration: {phase_agg.get_avg_encrypt_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Min Encryption Duration: {phase_agg.get_min_encrypt_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Max Encryption Duration: {phase_agg.get_max_encrypt_duration():.6f} seconds", aggregated_log)
                if phase_agg.get_avg_operation_duration() > 0:
                    log_message(f"- Average Operation Duration: {phase_agg.get_avg_operation_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Min Operation Duration: {phase_agg.get_min_operation_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Max Operation Duration: {phase_agg.get_max_operation_duration():.6f} seconds", aggregated_log)
                if phase_agg.get_avg_decrypt_duration() > 0:
                    log_message(f"- Average Decryption Duration: {phase_agg.get_avg_decrypt_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Min Decryption Duration: {phase_agg.get_min_decrypt_duration():.6f} seconds", aggregated_log)
                    log_message(f"- Max Decryption Duration: {phase_agg.get_max_decrypt_duration():.6f} seconds", aggregated_log)
                
                # Aggregate Memory and CPU using MetricsAggregated.
                log_message("### Additional Memory Usage", aggregated_log)
                log_message(f"- Average : {format_bytes(memory_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min : {format_bytes(memory_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(memory_agg.aggregated_max_of_avg())}", aggregated_log)
                
                log_message("### CPU Busy Percentage", aggregated_log)
                log_message(f"- Average : {cpu_agg.aggregated_avg():.2f}%", aggregated_log)
                log_message(f"- Min : {cpu_agg.aggregated_min_of_avg():.2f}%", aggregated_log)
                log_message(f"- Max : {cpu_agg.aggregated_max_of_avg():.2f}%", aggregated_log)
                
                # Aggregate Network metrics.
                log_message("### Network Metrics", aggregated_log)
                log_message("#### Bandwidth", aggregated_log)
                log_message(f"- Average : {format_bytes(net_sent_agg.aggregated_avg() + net_recv_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min : {format_bytes(net_sent_agg.aggregated_min_of_avg() + net_recv_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(net_sent_agg.aggregated_max_of_avg() + net_recv_agg.aggregated_max_of_avg())}", aggregated_log)

                log_message("#### Bytes Sent", aggregated_log)
                log_message(f"- Average : {format_bytes(net_sent_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min: {format_bytes(net_sent_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(net_sent_agg.aggregated_max_of_avg())}", aggregated_log)
                
                log_message("#### Bytes Received", aggregated_log)
                log_message(f"- Average : {format_bytes(net_recv_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min : {format_bytes(net_recv_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(net_recv_agg.aggregated_max_of_avg())}", aggregated_log)
                
                log_message("### Latency", aggregated_log)
                log_message(f"- Average : {net_latency_agg.aggregated_avg():.6f} ms", aggregated_log)
                log_message(f"- Min : {net_latency_agg.aggregated_min_of_avg():.6f} ms", aggregated_log)
                log_message(f"- Max : {net_latency_agg.aggregated_max_of_avg():.6f} ms", aggregated_log)

                log_message("### Disk I/O Metrics", aggregated_log)
                log_message("#### Disk Read", aggregated_log)
                log_message(f"- Average : {format_bytes(disk_read_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min : {format_bytes(disk_read_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(disk_read_agg.aggregated_max_of_avg())}", aggregated_log)

                log_message("#### Disk Write", aggregated_log)
                log_message(f"- Average : {format_bytes(disk_write_agg.aggregated_avg())}", aggregated_log)
                log_message(f"- Min : {format_bytes(disk_write_agg.aggregated_min_of_avg())}", aggregated_log)
                log_message(f"- Max : {format_bytes(disk_write_agg.aggregated_max_of_avg())}", aggregated_log)

                if BATTERY:
                    log_message("### Battery Consumption", aggregated_log)
                    log_message(f"- Average Battery Consumption: {battery_agg.aggregated_avg_of_sum():.6f} Joules", aggregated_log)
                
                # Plot aggregated time series graphs using the merged plot_metric function.
                plot_metric(cpu_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                plot_metric(memory_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                plot_metric(net_sent_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                plot_metric(net_recv_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                plot_metric(disk_read_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                plot_metric(disk_write_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                if BATTERY:
                    plot_metric(battery_agg, main_folder, isAggregated=True, phase_agg=phase_agg)
                
                print(Fore.RESET)
            
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
    result = dummy(range_mod=2**20, modulo=7, range_sum=2**20)
    print(Fore.BLUE + "Algorithm result:", result)
    print(Fore.RESET)
