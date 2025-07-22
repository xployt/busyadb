import subprocess
import sys
import os
import re
import platform
import json # For potential future structured data handling or command discovery caching

def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_ascii_art():
    """Print the toolkit's ASCII art logo."""
    ascii_art = r"""
 _     _ͯ̈͐👻-̜̾                                    
| |__  _  _ ___ _  _  __ _  __| | |__ 
| '_ \| | | / __| | | |/ _` |/ _` | '_ \
| |_) | |_| \__ \ |_| | (_| | (_| | |_) |
|_.__/ \__,_|___/\__, |\__,_|\__,_|_.__/
                 |___/                   """
    print(ascii_art)

def check_adb_device():
    """Verify ADB availability and device connection."""
    try:
        # Check if ADB executable exists
        subprocess.run(["adb", "version"], stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE, check=True, timeout=5)
        
        # Check connected devices
        result = subprocess.run(["adb", "devices"], capture_output=True, 
                               text=True, check=True, timeout=5)
        
        # Parse device list
        devices = [line.split('\t')[0] 
                   for line in result.stdout.splitlines() 
                   if '\tdevice' in line and not line.startswith('*')] # Exclude "daemon started successfully"
        
        if not devices:
            print("Error: No ADB devices found. Connect a device and try again.")
            return False
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: ADB not found or not in PATH. Install Android SDK and add to PATH.")
        return False
    except subprocess.TimeoutExpired:
        print("Error: ADB command timed out during device check. Check connection or ADB server status.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during ADB device check: {e}")
        return False

def run_adb_command(command, timeout=30, use_su=False, check_exit_code=True):
    """
    Execute ADB command with error handling, timeout, and optional 'su' retry.
    
    Args:
        command (str): The ADB command to execute (e.g., "shell ls /data").
                       If it's a shell command, it should start with "shell ".
        timeout (int): Timeout in seconds for the command.
        use_su (bool): If True, the command will be run with 'su -c'.
                       Used internally for retries.
        check_exit_code (bool): If True, consider non-zero exit codes as failures.
    
    Returns:
        tuple: (bool, str) - True if successful, False otherwise, and the output string.
    """
    if not check_adb_device():
        return False, "No ADB device connected."

    full_command = f"adb {command}"
    
    if use_su:
        if command.startswith("shell "):
            shell_cmd_inner = command[len("shell "):]
            # Escape single quotes and potentially other special characters for su -c
            # This can be tricky; a simpler approach might be to wrap the command in bash -c for more complex scenarios
            quoted_shell_cmd = shell_cmd_inner.replace("'", "'\\''")
            full_command = f"adb shell \"su -c '{quoted_shell_cmd}'\""
            print(f"Attempting to execute with root: {full_command}")
        else:
            print(f"Warning: 'su' retry requested for non-shell ADB command: {command}. Skipping 'su'.")
            use_su = False # Prevent further 'su' attempts for this path
            print(f"Attempting to execute: {full_command}")
    else:
        print(f"Attempting to execute: {full_command}")

    try:
        result = subprocess.run(
            full_command,
            shell=True, # Use shell=True for complex commands with quotes and pipes
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False # We handle check manually to retry with su
        )
        
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if check_exit_code and result.returncode != 0:
            error_message = f"Command failed (code {result.returncode}): {stderr}"
            print(f"Error: {error_message}")

            permission_denied_patterns = [
                "Permission denied", "permission denied", "Operation not permitted",
                "Read-only file system", "Access denied", "denied", "Operation not permitted"
            ]
            
            is_permission_error = any(re.search(pattern, stderr, re.IGNORECASE) for pattern in permission_denied_patterns)

            if is_permission_error and not use_su and command.startswith("shell "):
                print("Permission denied detected. Attempting to retry with 'su' (root privileges)...")
                return run_adb_command(command, timeout, use_su=True) # Recursive call
            
            return False, error_message
        
        # If exit code is 0 or check_exit_code is False, and no permission error on first attempt
        print(stdout)
        if stderr and not is_permission_error: # Print stderr if it exists and wasn't a permission issue we tried to elevate
            print(f"Note (stderr): {stderr}")
        return True, stdout
        
    except subprocess.TimeoutExpired:
        message = f"Error: Command timed out after {timeout} seconds."
        print(message)
        return False, message
    except Exception as e:
        message = f"Unexpected error during command execution: {str(e)}"
        print(message)
        return False, message

def handle_complex_shell_command(cmd, timeout=30, force_su=False):
    """
    Executes a complex shell command on the device, allowing 'su' retry.
    This function wraps the command in 'adb shell' automatically.
    
    Args:
        cmd (str): The shell command string to execute on the device.
        timeout (int): Timeout in seconds.
        force_su (bool): If True, directly attempts with 'su -c' first.
    
    Returns:
        bool: True if successful, False otherwise.
    """
    # Pass the full "shell {cmd}" string to run_adb_command
    success, _ = run_adb_command(f'shell "{cmd}"', timeout, use_su=force_su)
    return success

def get_valid_input(prompt, valid_options=None, allow_empty=False):
    """
    Gets validated user input.
    
    Args:
        prompt (str): The message to display to the user.
        valid_options (list, optional): A list of valid input strings.
                                        If None, any input is accepted.
        allow_empty (bool): If True, an empty string is considered valid.
    
    Returns:
        str: The validated user input, or None if cancelled/error.
    """
    while True:
        try:
            choice = input(prompt).strip()
            if not choice and allow_empty:
                return choice
            if valid_options and choice not in valid_options:
                print(f"Invalid option. Valid options: {', '.join(valid_options)}")
                continue
            if not choice and not allow_empty:
                print("Input cannot be empty. Please try again.")
                continue
            return choice
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return None
        except Exception as e:
            print(f"Input error: {str(e)}")
            return None

# --- New Global Variables for Discovered Commands ---
AVAILABLE_SHELL_COMMANDS = []
BUSYBOX_COMMANDS = []

def discover_shell_commands():
    """
    Attempts to discover common shell commands and BusyBox commands on the device.
    This helps make the toolkit dynamic.
    """
    print("Discovering available shell commands on the device...")
    global AVAILABLE_SHELL_COMMANDS
    global BUSYBOX_COMMANDS

    # Common paths for binaries
    paths_to_check = "/system/bin:/system/xbin:/vendor/bin:/sbin:/bin"
    
    # Try to find common utilities directly
    common_cmds = ["ls", "cat", "grep", "find", "ps", "top", "ip", "netstat", "df", "du", 
                   "uname", "id", "which", "getprop", "mount", "logcat", "dumpsys", 
                   "pm", "am", "monkey", "screencap", "screenrecord", "ping", "nslookup", "dig"]

    # First, try to get all executables from common paths
    # This might be slow or produce a lot of output, limit to common paths
    success, output = run_adb_command(f"shell 'echo $PATH'", check_exit_code=False, timeout=10)
    if success and output:
        device_path = output
        print(f"Device PATH: {device_path}")
        # Iterate through paths in $PATH to find executables
        for path_dir in device_path.split(':'):
            if path_dir: # Ensure not empty string
                # List executables in each path
                list_cmd = f'ls -F "{path_dir}" | grep "*$"' # List files, grep for '*' which indicates executable
                s, o = run_adb_command(f"shell '{list_cmd}'", check_exit_code=False, timeout=20)
                if s and o:
                    executables = [f.strip('*') for f in o.splitlines() if f.strip('*')]
                    AVAILABLE_SHELL_COMMANDS.extend(executables)
    else:
        print("Could not retrieve device PATH. Using a predefined list of common commands.")
        AVAILABLE_SHELL_COMMANDS = common_cmds # Fallback to a predefined list

    # Add busybox commands if busybox is found
    success, output = run_adb_command("shell 'which busybox'", check_exit_code=False, timeout=5)
    if success and output and "busybox" in output:
        print("BusyBox detected. Discovering BusyBox commands...")
        # Get list of busybox applets
        s, o = run_adb_command("shell 'busybox --list'", check_exit_code=False, timeout=10)
        if s and o:
            BUSYBOX_COMMANDS = [cmd.strip() for cmd in o.splitlines() if cmd.strip()]
            AVAILABLE_SHELL_COMMANDS.extend(BUSYBOX_COMMANDS)
    else:
        print("BusyBox not found or command failed.")

    # Remove duplicates and sort
    AVAILABLE_SHELL_COMMANDS = sorted(list(set(AVAILABLE_SHELL_COMMANDS)))
    BUSYBOX_COMMANDS = sorted(list(set(BUSYBOX_COMMANDS)))
    print(f"Discovered {len(AVAILABLE_SHELL_COMMANDS)} unique shell commands.")
    print("\n")


# --- Menu Functions ---

def system_info_menu():
    """Menu for system information and health monitoring."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- System Information ---")
        print("1. System Health Monitor (Top Processes)")
        print("2. Hardware Information (getprop & CPU info)")
        print("3. Network Status (IP, Netstat)")
        print("4. Memory Usage (cat /proc/meminfo)")
        print("5. Storage Information (df -h)")
        print("6. Kernel Version (uname -a)")
        print("7. All System Properties (getprop full dump)")
        print("8. Running Services (service list)")
        print("9. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 10)])
        if not choice:
            continue
            
        if choice == '1':
            handle_complex_shell_command("top -n 1") # Show top processes once
        elif choice == '2':
            handle_complex_shell_command("getprop")
            handle_complex_shell_command("cat /proc/cpuinfo")
        elif choice == '3':
            handle_complex_shell_command("ip addr show")
            handle_complex_shell_command("netstat -tunlp")
        elif choice == '4':
            handle_complex_shell_command("cat /proc/meminfo")
        elif choice == '5':
            handle_complex_shell_command("df -h")
            handle_complex_shell_command("du -h -d 1 /sdcard 2>/dev/null") # Common user storage, max depth 1
        elif choice == '6':
            handle_complex_shell_command("uname -a")
        elif choice == '7':
            handle_complex_shell_command("getprop")
        elif choice == '8':
            handle_complex_shell_command("service list")
        elif choice == '9':
            break
        
        input("\nPress Enter to continue...")

def file_directory_menu():
    """Menu for file and directory management."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- File Management ---")
        print("1. List Directory Contents (ls -la)")
        print("2. Find File/Directory")
        print("3. Disk Usage (df -h, du -h)")
        print("4. View File Content (cat/head/tail)")
        print("5. Create Directory (mkdir -p)")
        print("6. Delete File/Directory (rm -rf)")
        print("7. Pull File from Device to PC")
        print("8. Push File from PC to Device")
        print("9. Create Empty File (touch)")
        print("10. Move/Rename File (mv)")
        print("11. Copy File (cp)")
        print("12. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 13)])
        if not choice:
            continue
            
        if choice == '1':
            path = input("Enter directory path (e.g., /sdcard/Download, default /): ").strip() or "/"
            handle_complex_shell_command(f'ls -la "{path}"')
        elif choice == '2':
            filename = input("Enter filename/directory name to search (e.g., my_file.txt or my_folder): ").strip()
            if filename:
                search_depth = get_valid_input("Enter max search depth (e.g., 3, 0 for unlimited, default 5): ", allow_empty=True) or "5"
                if search_depth.isdigit():
                    depth_option = f"-maxdepth {search_depth}" if search_depth != "0" else ""
                    handle_complex_shell_command(f'find / -name "{filename}" {depth_option} 2>/dev/null')
                else:
                    print("Invalid depth. Using default.")
        elif choice == '3':
            handle_complex_shell_command("df -h")
            path_for_du = input("Enter path for 'du -h' (e.g., /sdcard, default /): ").strip() or "/"
            handle_complex_shell_command(f'du -h "{path_for_du}"')
        elif choice == '4':
            path = input("Enter file path to view (e.g., /sdcard/log.txt): ").strip()
            if path:
                view_type = get_valid_input("View (c)at, (h)ead, or (t)ail? (c/h/t): ", ["c", "h", "t"])
                if view_type == 'c':
                    handle_complex_shell_command(f'cat "{path}"')
                elif view_type == 'h':
                    lines = get_valid_input("Number of lines for head (default 10): ", allow_empty=True) or "10"
                    handle_complex_shell_command(f'head -n {lines} "{path}"')
                elif view_type == 't':
                    lines = get_valid_input("Number of lines for tail (default 10): ", allow_empty=True) or "10"
                    handle_complex_shell_command(f'tail -n {lines} "{path}"')
        elif choice == '5':
            path = input("Enter new directory path (e.g., /sdcard/new_folder): ").strip()
            if path:
                handle_complex_shell_command(f'mkdir -p "{path}"')
        elif choice == '6':
            path = input("Enter file/directory path to delete (USE WITH EXTREME CAUTION! e.g., /sdcard/old_file.txt): ").strip()
            if path:
                confirm = get_valid_input(f"Are you sure you want to delete '{path}'? This cannot be undone! (y/n): ", ["y", "n"])
                if confirm == 'y':
                    handle_complex_shell_command(f'rm -rf "{path}"')
                else:
                    print("Deletion cancelled.")
        elif choice == '7':
            remote_path = input("Enter remote file path on device (e.g., /sdcard/document.pdf): ").strip()
            local_path = input("Enter local path to save on PC (e.g., ./downloaded_file.pdf): ").strip()
            if remote_path and local_path:
                success, _ = run_adb_command(f'pull "{remote_path}" "{local_path}"')
                if success:
                    print(f"File successfully pulled to {local_path}")
                else:
                    print("Failed to pull file.")
        elif choice == '8':
            local_path = input("Enter local file path on PC (e.g., ./my_app.apk): ").strip()
            remote_path = input("Enter remote path on device (e.g., /sdcard/uploads/): ").strip()
            if local_path and remote_path:
                if not os.path.exists(local_path):
                    print(f"Error: Local file '{local_path}' does not exist.")
                else:
                    success, _ = run_adb_command(f'push "{local_path}" "{remote_path}"')
                    if success:
                        print(f"File successfully pushed to {remote_path}")
                    else:
                        print("Failed to push file.")
        elif choice == '9':
            path = input("Enter path for new empty file (e.g., /sdcard/new_file.txt): ").strip()
            if path:
                handle_complex_shell_command(f'touch "{path}"')
        elif choice == '10':
            old_path = input("Enter current file/directory path: ").strip()
            new_path = input("Enter new file/directory path: ").strip()
            if old_path and new_path:
                handle_complex_shell_command(f'mv "{old_path}" "{new_path}"')
        elif choice == '11':
            source_path = input("Enter source file path on device: ").strip()
            destination_path = input("Enter destination path on device: ").strip()
            if source_path and destination_path:
                handle_complex_shell_command(f'cp -r "{source_path}" "{destination_path}"') # -r for directories
        elif choice == '12':
            break
            
        input("\nPress Enter to continue...")

def networking_menu():
    """Menu for network diagnostic tools."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- Networking Tools ---")
        print("1. Ping Host")
        print("2. View Network Interfaces (ip addr show)")
        print("3. Show Open Ports & Connections (netstat -anp)")
        print("4. DNS Lookup (nslookup/dig)")
        print("5. Wi-Fi Connection Info (dumpsys wifi)")
        print("6. Route Table (ip route)")
        print("7. TCP/UDP Listener (netcat/nc - listen)")
        print("8. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 9)])
        if not choice:
            continue
            
        if choice == '1':
            host = input("Enter host to ping (e.g., google.com or 8.8.8.8): ").strip()
            if host:
                handle_complex_shell_command(f'ping -c 4 "{host}"') # Ping 4 times
        elif choice == '2':
            handle_complex_shell_command("ip addr show")
        elif choice == '3':
            handle_complex_shell_command("netstat -anp") # Show all connections, numeric, programs
        elif choice == '4':
            domain = input("Enter domain for DNS lookup: ").strip()
            if domain:
                # Android often has 'nslookup' or 'dig' via busybox or similar
                handle_complex_shell_command(f'nslookup "{domain}" || dig "{domain}"')
        elif choice == '5':
            handle_complex_shell_command("dumpsys wifi")
        elif choice == '6':
            handle_complex_shell_command("ip route show")
        elif choice == '7':
            print("Note: This requires 'netcat' or 'nc' to be available on the device.")
            port = input("Enter port to listen on: ").strip()
            if port.isdigit():
                print(f"Listening on port {port}. Press Ctrl+C to stop.")
                # This will block indefinitely or until timeout/Ctrl+C
                handle_complex_shell_command(f'nc -l -p {port}', timeout=0) # Use 0 for indefinite timeout for listeners
            else:
                print("Invalid port.")
        elif choice == '8':
            break
            
        input("\nPress Enter to continue...")

def process_automation_menu():
    """Menu for managing processes and applications."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- Process Management ---")
        print("1. List All Processes (ps -Af)")
        print("2. Find Process by Name (grep)")
        print("3. Kill Process by PID")
        print("4. Force Stop Application by Package Name")
        print("5. Start Application by Package Name")
        print("6. View Process Details by PID (cat /proc/<pid>/status)")
        print("7. List Running Services (dumpsys activity services)")
        print("8. List All Packages (pm list packages)")
        print("9. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 10)])
        if not choice:
            continue
            
        if choice == '1':
            handle_complex_shell_command("ps -Af") # List all processes with user/cpu/mem
        elif choice == '2':
            name = input("Enter process name (e.g., com.android.chrome): ").strip()
            if name:
                handle_complex_shell_command(f'ps -Af | grep "{name}"')
        elif choice == '3':
            pid = input("Enter PID to kill: ").strip()
            if pid and pid.isdigit():
                confirm = get_valid_input(f"Are you sure you want to kill PID {pid}? (y/n): ", ["y", "n"])
                if confirm == 'y':
                    handle_complex_shell_command(f'kill {pid}')
                else:
                    print("Kill operation cancelled.")
            else:
                print("Invalid PID. Please enter a number.")
        elif choice == '4':
            package = input("Enter package name to force stop (e.g., com.android.chrome): ").strip()
            if package:
                handle_complex_shell_command(f'am force-stop "{package}"')
        elif choice == '5':
            package = input("Enter package name to start (e.g., com.android.chrome): ").strip()
            if package:
                # This tries to launch the default activity of the package
                handle_complex_shell_command(f'monkey -p "{package}" 1')
        elif choice == '6':
            pid = input("Enter PID to view details: ").strip()
            if pid and pid.isdigit():
                handle_complex_shell_command(f'cat /proc/{pid}/status')
            else:
                print("Invalid PID. Please enter a number.")
        elif choice == '7':
            handle_complex_shell_command("dumpsys activity services")
        elif choice == '8':
            handle_complex_shell_command("pm list packages -f") # -f to show path
        elif choice == '9':
            break
            
        input("\nPress Enter to continue...")

def security_user_menu():
    """Menu for security checks and user-related information."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- Security & User Tools ---")
        print("1. List Installed Packages (pm list packages)")
        print("2. Check Device Root Status (which su, id)")
        print("3. List Permissions for a Package (dumpsys package)")
        print("4. View Device Logs (Logcat - Dump)")
        print("5. Check SELinux Status (getenforce)")
        print("6. List User Accounts (pm list users)")
        print("7. View Current User ID (id)")
        print("8. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 9)])
        if not choice:
            continue
            
        if choice == '1':
            handle_complex_shell_command("pm list packages -f") # -f for path
        elif choice == '2':
            print("Checking for 'su' binary and current user ID:")
            handle_complex_shell_command("which su") # Checks if 'su' binary exists in PATH
            handle_complex_shell_command("id") # Shows current user ID (0 for root)
        elif choice == '3':
            package = input("Enter package name to list permissions (e.g., com.android.settings): ").strip()
            if package:
                handle_complex_shell_command(f'dumpsys package "{package}" | grep "permission"')
        elif choice == '4':
            print("Dumping recent device logs (Logcat).")
            handle_complex_shell_command("logcat -d") # Use 'logcat -d' to dump and exit
        elif choice == '5':
            handle_complex_shell_command("getenforce")
        elif choice == '6':
            handle_complex_shell_command("pm list users")
        elif choice == '7':
            handle_complex_shell_command("id")
        elif choice == '8':
            break
            
        input("\nPress Enter to continue...")

def development_debugging_menu():
    """Menu for development and debugging utilities."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- Development & Debugging Tools ---")
        print("1. View Full Device Logs (Logcat - Continuous)")
        print("2. Take Screenshot")
        print("3. Record Screen")
        print("4. Install APK from PC")
        print("5. Uninstall Package")
        print("6. Reboot Device")
        print("7. Clear App Data (pm clear)")
        print("8. Enable/Disable ADB over TCP/IP")
        print("9. Back to Main Menu")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 10)])
        if not choice:
            continue
            
        if choice == '1':
            print("Viewing continuous device logs (Logcat). This will run until you press Ctrl+C or it times out.")
            run_adb_command("logcat", timeout=300) # 5 minutes timeout for continuous logs
            print("Logcat session ended.")
        elif choice == '2':
            filename = input("Enter filename for screenshot on device (e.g., /sdcard/screenshot.png, default /sdcard/screenshot.png): ").strip() or "/sdcard/screenshot.png"
            if filename:
                handle_complex_shell_command(f'screencap -p "{filename}"')
                print(f"Screenshot saved to {filename} on device. You can pull it using 'File Management > Pull File'.")
        elif choice == '3':
            duration = input("Enter recording duration in seconds (max 180, e.g., 10): ").strip()
            if duration.isdigit() and 1 <= int(duration) <= 180:
                filename = input("Enter filename for video on device (e.g., /sdcard/screenrecord.mp4, default /sdcard/screenrecord.mp4): ").strip() or "/sdcard/screenrecord.mp4"
                print(f"Recording screen for {duration} seconds to {filename}...")
                handle_complex_shell_command(f'screenrecord --time-limit {duration} "{filename}"')
                print(f"Screen recording saved to {filename} on device. You can pull it using 'File Management > Pull File'.")
            else:
                print("Invalid duration. Please enter a number between 1 and 180.")
        elif choice == '4':
            apk_path = input("Enter local path to APK file on PC (e.g., ./my_app.apk): ").strip()
            if apk_path:
                if not os.path.exists(apk_path):
                    print(f"Error: Local APK file '{apk_path}' does not exist.")
                else:
                    success, _ = run_adb_command(f'install "{apk_path}"')
                    if success:
                        print(f"APK '{apk_path}' installed successfully.")
                    else:
                        print("Failed to install APK.")
        elif choice == '5':
            package = input("Enter package name to uninstall (e.g., com.example.myapp): ").strip()
            if package:
                confirm = get_valid_input(f"Are you sure you want to uninstall '{package}'? (y/n): ", ["y", "n"])
                if confirm == 'y':
                    success, _ = run_adb_command(f'uninstall "{package}"')
                    if success:
                        print(f"Package '{package}' uninstalled successfully.")
                    else:
                        print("Failed to uninstall package.")
                else:
                    print("Uninstallation cancelled.")
        elif choice == '6':
            confirm = get_valid_input("Are you sure you want to reboot the device? This will disconnect ADB temporarily. (y/n): ", ["y", "n"])
            if confirm == 'y':
                print("Rebooting device...")
                run_adb_command("reboot")
                print("Device reboot command sent. It may take a moment to reconnect. You might need to restart the toolkit.")
            else:
                print("Reboot cancelled.")
        elif choice == '7':
            package = input("Enter package name to clear data for (e.g., com.example.myapp): ").strip()
            if package:
                confirm = get_valid_input(f"Are you sure you want to clear data for '{package}'? This will reset the app. (y/n): ", ["y", "n"])
                if confirm == 'y':
                    handle_complex_shell_command(f'pm clear "{package}"')
                else:
                    print("Clear data operation cancelled.")
        elif choice == '8':
            mode = get_valid_input("Enable (e) or Disable (d) ADB over TCP/IP? (e/d): ", ["e", "d"])
            if mode == 'e':
                port = input("Enter port (default 5555): ").strip() or "5555"
                print(f"Enabling ADB over TCP/IP on port {port}. Disconnect USB and reconnect via 'adb connect <device_ip>:{port}'.")
                run_adb_command(f"tcpip {port}")
            elif mode == 'd':
                print("Disabling ADB over TCP/IP (reverting to USB mode).")
                run_adb_command("usb")
            else:
                print("Invalid option.")
        elif choice == '9':
            break
            
        input("\nPress Enter to continue...")

def advanced_shell_menu():
    """Menu for executing arbitrary shell commands."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- Advanced Shell Access ---")
        print("Execute arbitrary shell commands. Use with caution.")
        print("Type 'list' to see discovered common commands.")
        print("Type 'back' to return to Main Menu.")
        
        command_input = get_valid_input("\nEnter shell command to execute: ", allow_empty=True).strip()
        
        if command_input.lower() == 'back':
            break
        elif command_input.lower() == 'list':
            print("\n--- Discovered Shell Commands ---")
            for i, cmd in enumerate(AVAILABLE_SHELL_COMMANDS):
                print(f"{i+1}. {cmd}")
            print("---------------------------------")
            input("\nPress Enter to continue...")
            continue
        elif not command_input:
            print("No command entered. Please enter a command or 'back'.")
            continue
        
        force_root = get_valid_input("Attempt to run with root (su -c) if permissions fail? (y/n): ", ["y", "n"]) == 'y'
        
        # We assume command_input is a shell command, so prefix with "shell "
        handle_complex_shell_command(command_input, force_su=force_root)
        
        input("\nPress Enter to continue...")

def main_menu():
    """Main menu with exit confirmation."""
    while True:
        clear_screen()
        print_ascii_art()
        print("--- busyadb Main Menu ---")
        print("1. System Information")
        print("2. File Management")
        print("3. Networking Tools")
        print("4. Process Management")
        print("5. Security & User Tools")
        print("6. Development & Debugging Tools")
        print("7. Advanced Shell Access") # New option
        print("8. Exit")
        
        choice = get_valid_input("Choose an option: ", [str(i) for i in range(1, 9)])
        if not choice:
            continue
            
        if choice == '1':
            system_info_menu()
        elif choice == '2':
            file_directory_menu()
        elif choice == '3':
            networking_menu()
        elif choice == '4':
            process_automation_menu()
        elif choice == '5':
            security_user_menu()
        elif choice == '6':
            development_debugging_menu()
        elif choice == '7':
            advanced_shell_menu()
        elif choice == '8':
            confirm = get_valid_input("Are you sure you want to exit busyadb? (y/n): ", ["y", "n"])
            if confirm == 'y':
                sys.exit("Exiting busyadb. Goodbye!")
            else:
                print("Returning to main menu.")

if __name__ == "__main__":
    try:
        if check_adb_device():
            discover_shell_commands() # Discover commands at startup
            main_menu()
        else:
            print("\nADB device not connected or ADB not found. Please resolve this to use the toolkit.")
            input("Press Enter to exit...")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nProgram terminated by user (Ctrl+C).")
        sys.exit(1)
    except Exception as e:
        print(f"Critical error: {str(e)}")
        sys.exit(1)