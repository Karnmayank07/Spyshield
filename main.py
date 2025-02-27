import psutil
import os
import logging

# Setup logging
logging.basicConfig(filename="detection.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# List of critical system processes that should NEVER be terminated
CRITICAL_PROCESSES = [
    "winlogon.exe", "explorer.exe", "services.exe", "csrss.exe", "smss.exe",
    "lsass.exe", "wininit.exe", "svchost.exe", "taskmgr.exe", "dwm.exe",
    "WUDFHost.exe", "ipfsvc.exe"
]

# Function to check if a process is safe
def is_critical_process(process_name):
    return process_name.lower() in CRITICAL_PROCESSES

# Function to terminate suspicious processes safely
def terminate_process(pid, process_name):
    if is_critical_process(process_name):
        print(f"[⚠] WARNING: {process_name} (PID: {pid}) is a critical system process. Termination blocked.")
        logging.warning(f"Attempt to terminate critical process blocked: {process_name} (PID: {pid})")
        return
    
    try:
        proc = psutil.Process(pid)
        proc.terminate()  # Attempt soft termination
        proc.wait(3)  # Wait a few seconds before checking
        if proc.is_running():
            proc.kill()  # Force kill if still running
        print(f"[✔] Successfully terminated: {process_name} (PID: {pid})")
        logging.info(f"Terminated: {process_name} (PID: {pid})")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        print(f"[⚠] Failed to terminate: {process_name} (PID: {pid}). Try running as Admin.")
        logging.warning(f"Failed to terminate process: {process_name} (PID: {pid})")

# Function to detect suspicious processes
def detect_suspicious_processes():
    suspicious_keywords = ['keylogger', 'logkeys', 'xinput', 'hook', 'capture', 'spy', 'record']
    detected_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            process_name = proc.info['name'].lower()
            process_path = proc.info['exe'] if proc.info['exe'] else "Unknown Path"
            process_user = proc.info['username'] if proc.info['username'] else "Unknown User"

            # Check if the process name contains a suspicious keyword
            if any(keyword in process_name for keyword in suspicious_keywords):
                alert_message = f"[!] Suspicious process detected: {process_name} (PID: {proc.info['pid']}), Path: {process_path}, User: {process_user}"
                print(alert_message)
                logging.info(alert_message)
                detected_processes.append(proc.info['pid'])

                # Ask user before termination
                user_input = input(f"⚠️ Do you want to terminate {process_name} (PID: {proc.info['pid']})? (yes/no): ").strip().lower()
                if user_input in ['yes', 'y']:
                    terminate_process(proc.info['pid'], process_name)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return detected_processes

# Function to check for suspicious network activity
def detect_suspicious_network_activity():
    suspicious_connections = []
    safe_ports = [80, 443]  # HTTP and HTTPS

    print("\n🔍 Scanning for suspicious network activity...")

    for conn in psutil.net_connections(kind='inet'):
        try:
            pid = conn.pid
            if pid and conn.status == 'ESTABLISHED':  # Active network connection
                process = psutil.Process(pid)
                process_name = process.name()
                remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
                remote_port = conn.raddr.port if conn.raddr else "Unknown"

                # Flag any process communicating on non-standard ports
                if remote_port not in safe_ports:
                    alert_message = f"[!] Suspicious network activity: {process_name} (PID: {pid}) → {remote_ip}:{remote_port}"
                    print(alert_message)
                    logging.warning(alert_message)
                    suspicious_connections.append((process_name, pid, remote_ip, remote_port))

                    # Ask user before termination
                    user_input = input(f"⚠️ Do you want to terminate {process_name} (PID: {pid})? (yes/no): ").strip().lower()
                    if user_input in ['yes', 'y']:
                        terminate_process(pid, process_name)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not suspicious_connections:
        print("[✔] No suspicious network activity found.")
    else:
        print(f"⚠️ Detected {len(suspicious_connections)} suspicious network activities.")

# Main function
def main():
    print("🔍 Running Safe Keylogger & Network Detection...\n")

    detected_pids = detect_suspicious_processes()
    detect_suspicious_network_activity()

    if detected_pids:
        print(f"⚠️ Detected {len(detected_pids)} suspicious processes. Check 'detection.log' for details.")
    else:
        print("[✔] No suspicious processes found.")

    print("\n[+] Scan complete.")

if __name__ == "__main__":
    main()



