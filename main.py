import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import socket
from threading import Thread, Event
import requests
import os

# Global variables
stop_event = Event()  # Used to stop the scan
results_text = ""  # To store results for saving

# Function to scan ports
def scan_ports():
    global results_text
    target = entry_target.get()
    port_range = entry_port_range.get()

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except ValueError:
        messagebox.showerror("Error", "Invalid port range format. Use 'start-end'.")
        return

    results.delete(1.0, tk.END)  # Clear previous results
    progress['value'] = 0  # Reset progress bar
    total_ports = end_port - start_port + 1
    results_text = ""  # Reset results text

    def scan():
        global results_text
        open_ports = []
        for port in range(start_port, end_port + 1):
            if stop_event.is_set():  # Check if stop button was pressed
                results.insert(tk.END, "\nScan stopped by user.\n")
                return

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    banner = get_service_banner(sock, port)
                    cves = get_cves(port)
                    open_ports.append(port)
                    result_line = f"Port {port}: Open ({banner})\n{cves}\n"
                    results.insert(tk.END, result_line)
                    results_text += result_line
                sock.close()
            except Exception as e:
                results.insert(tk.END, f"Port {port}: Error ({str(e)})\n")
                results_text += f"Port {port}: Error ({str(e)})\n"

            progress['value'] = (port - start_port + 1) / total_ports * 100
            root.update_idletasks()  # Update the GUI

        if open_ports:
            messagebox.showinfo("Scan Complete", f"Open ports: {', '.join(map(str, open_ports))}")
        else:
            messagebox.showinfo("Scan Complete", "No open ports found.")

    # Run the scan in a separate thread to keep the GUI responsive
    stop_event.clear()  # Reset stop event
    Thread(target=scan).start()

# Function to stop the scan
def stop_scan():
    stop_event.set()  # Signal the scan to stop

# Function to detect service banner
def get_service_banner(sock, port):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')  # Send a basic HTTP request
        banner = sock.recv(1024).decode().strip()
        return banner or "No banner detected"
    except:
        return "No banner detected"

# Function to fetch CVEs for a port
def get_cves(port):
    try:
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=port+{port}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            cves = data.get("result", {}).get("CVE_Items", [])
            if cves:
                return "\n".join([f"CVE ID: {cve['cve']['CVE_data_meta']['ID']}" for cve in cves])
            else:
                return "No CVEs found."
        else:
            return "Failed to fetch CVEs."
    except:
        return "Failed to fetch CVEs."

# Function to save results to a file
def save_results():
    folder_path = filedialog.askdirectory(title="Select Folder to Save Results")
    if not folder_path:
        return

    file_path = os.path.join(folder_path, "scan_results.txt")
    try:
        with open(file_path, mode='w') as file:
            file.write(results_text)
        messagebox.showinfo("Success", f"Results saved to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results: {e}")

# Create the main window
root = tk.Tk()
root.title("Ghost Port Scanner")
root.geometry("700x600")
root.configure(bg="red")  # Set background color to red

# Title Label
label_title = tk.Label(root, text="Ghost Port Scanner", font=("Arial", 20, "bold"), fg="white", bg="red")
label_title.pack(pady=10)

# Tagline Label
label_tagline = tk.Label(root, text="Developed by Shaheer Yasir", font=("Arial", 10), fg="white", bg="red")
label_tagline.pack()

# Label and Entry for Target IP/Domain
label_target = tk.Label(root, text="Target IP/Domain:", font=("Arial", 12), fg="white", bg="red")
label_target.pack(pady=5)
entry_target = tk.Entry(root, width=50, font=("Arial", 10))
entry_target.pack(pady=5)

# Label and Entry for Port Range
label_port_range = tk.Label(root, text="Port Range (e.g., 20-100):", font=("Arial", 12), fg="white", bg="red")
label_port_range.pack(pady=5)
entry_port_range = tk.Entry(root, width=50, font=("Arial", 10))
entry_port_range.pack(pady=5)

# Buttons Frame
buttons_frame = tk.Frame(root, bg="red")
buttons_frame.pack(pady=10)

button_scan = tk.Button(buttons_frame, text="Start Scan", command=scan_ports, font=("Arial", 12), bg="darkred", fg="white")
button_scan.grid(row=0, column=0, padx=5)

button_stop = tk.Button(buttons_frame, text="Stop Scan", command=stop_scan, font=("Arial", 12), bg="darkred", fg="white")
button_stop.grid(row=0, column=1, padx=5)

button_save = tk.Button(buttons_frame, text="Save Results", command=save_results, font=("Arial", 12), bg="darkred", fg="white")
button_save.grid(row=0, column=2, padx=5)

# Progress Bar
progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress.pack(pady=10)

# Results Text Area
results = tk.Text(root, height=15, width=80, font=("Arial", 10), bg="black", fg="white")
results.pack(pady=10)

# Run the application
root.mainloop()