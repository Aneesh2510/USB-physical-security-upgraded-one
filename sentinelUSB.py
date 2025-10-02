from datetime import datetime
import os
import sys
import re
import time
import hashlib
import random
import string
import smtplib
import threading
import queue
import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext

import requests

# --- APPLICATION CONFIGURATION ---
# It's better to load these from a secure config file in a real application
# For this self-contained script, we define them here.
ADMIN_USERNAME = "ani2510"
# IMPORTANT: Change this default password!
ADMIN_PASSWORD = "ANEESH2006" 
LOG_FILE = "sentinel_usb_log.txt"
# IMPORTANT: You MUST replace this with your own free key from virustotal.com
VT_API_KEY = "8b5023f70aca9a89172347f1c99f65f06eeda209b40547025a1d480500c073bf"

class SentinelApp:
    """
    An advanced USB Security and Malware Scanning application.
    Features a dashboard, real-time logging, and background threat scanning.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelUSB v1.0")
        self.root.geometry("600x650")
        self.root.resizable(False, False)
        
        # --- Application State ---
        self.login_attempts = 0
        self.credentials = {"email": None, "password": None}
        self.drive_queue = queue.Queue()
        self.is_monitoring = False
        
        # Initialize UI
        self.create_login_frame()
        self.create_dashboard_frame()

        # Show the login screen first
        self.login_frame.pack(fill="both", expand=True)

    # --- UI Creation ---

    def create_login_frame(self):
        self.login_frame = tk.Frame(self.root, bg="#2c3e50")
        
        tk.Label(self.login_frame, text="SentinelUSB Admin Login", font=("Helvetica", 18, "bold"), bg="#2c3e50", fg="white").pack(pady=(50, 20))
        
        tk.Label(self.login_frame, text="Username", bg="#2c3e50", fg="white").pack(pady=(10,0))
        self.username_entry = tk.Entry(self.login_frame, font=("Helvetica", 12))
        self.username_entry.pack(pady=5, padx=50, ipady=4)
        
        tk.Label(self.login_frame, text="Password", bg="#2c3e50", fg="white").pack(pady=(10,0))
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Helvetica", 12))
        self.password_entry.pack(pady=5, padx=50, ipady=4)
        
        tk.Button(self.login_frame, text="Login", command=self.handle_login, font=("Helvetica", 12, "bold"), bg="#1abc9c", fg="white", relief="flat", width=15).pack(pady=20)

    def create_dashboard_frame(self):
        self.dashboard_frame = tk.Frame(self.root, bg="#34495e")
        
        # --- Status Panel ---
        status_panel = tk.Frame(self.dashboard_frame, bg="#2c3e50", relief="raised", bd=1)
        status_panel.pack(fill="x", padx=10, pady=10, ipady=5)
        
        self.usb_status_label = tk.Label(status_panel, text="USB Ports: UNKNOWN", font=("Helvetica", 12), bg="#2c3e50", fg="white")
        self.usb_status_label.pack(side="left", padx=20)
        self.scanner_status_label = tk.Label(status_panel, text="Scanner: IDLE", font=("Helvetica", 12), bg="#2c3e50", fg="white")
        self.scanner_status_label.pack(side="right", padx=20)
        
        # --- Control Panel ---
        control_panel = tk.Frame(self.dashboard_frame, bg="#34495e")
        control_panel.pack(pady=20)
        
        self.enable_btn = tk.Button(control_panel, text="Enable USB Ports", command=self.handle_enable_usb, font=("Helvetica", 12, "bold"), bg="#27ae60", fg="white", width=20, height=2, relief="flat")
        self.enable_btn.grid(row=0, column=0, padx=15)
        self.disable_btn = tk.Button(control_panel, text="Disable USB Ports", command=self.handle_disable_usb, font=("Helvetica", 12, "bold"), bg="#c0392b", fg="white", width=20, height=2, relief="flat")
        self.disable_btn.grid(row=0, column=1, padx=15)

        # --- Log Viewer ---
        log_frame = tk.Frame(self.dashboard_frame, bg="#34495e")
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        tk.Label(log_frame, text="Real-Time Activity Log", font=("Helvetica", 12, "bold"), bg="#34495e", fg="white").pack()
        self.log_viewer = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', font=("Consolas", 10), bg="#2c3e50", fg="white", relief="flat")
        self.log_viewer.pack(pady=5, fill="both", expand=True)
    
    # --- Logic and Handlers ---

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.login_attempts >= 5:
            messagebox.showerror("Lockout", "Too many failed login attempts. The application will now exit.")
            self.root.destroy()
            return
            
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            self.login_frame.pack_forget()
            self.dashboard_frame.pack(fill="both", expand=True)
            self.log_action("Admin login successful.")
        else:
            self.login_attempts += 1
            self.log_action(f"Failed login attempt ({self.login_attempts}/5).")
            messagebox.showerror("Login Failed", f"Invalid credentials. You have {5 - self.login_attempts} attempts remaining.")

    def handle_enable_usb(self):
        self.execute_usb_action("enable")

    def handle_disable_usb(self):
        self.execute_usb_action("disable")

    def execute_usb_action(self, action):
        if not self.get_email_credentials():
            return

        otp = self.generate_otp()
        success = self.send_email("SentinelUSB: Your One-Time Code", f"Your verification code is: {otp}\nThis code is valid for 5 minutes.", self.credentials["email"])
        
        if not success:
            return

        entered_otp = simpledialog.askstring("Two-Factor Authentication", "Enter the code sent to your email:", show='*')
        if entered_otp == otp:
            self.log_action(f"2FA successful. Executing '{action}' action.")
            try:
                if action == "enable":
                    os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 3 /f')
                    self.update_dashboard_status("USB Ports: ENABLED", "green", "Scanner: MONITORING", "orange")
                    self.start_drive_monitoring()
                else: # disable
                    os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f')
                    self.is_monitoring = False # Stop monitoring
                    self.update_dashboard_status("USB Ports: DISABLED", "red", "Scanner: IDLE", "gray")
                self.log_action(f"USB ports successfully {action}d.")
            except Exception as e:
                self.log_action(f"ERROR: Failed to {action} USB ports: {e}")
                messagebox.showerror("Registry Error", f"Failed to modify registry. Please run as Administrator.\nError: {e}")
        else:
            self.log_action("2FA failed. Incorrect code entered.")
            messagebox.showerror("Access Denied", "The entered code was incorrect.")

    # --- Backend and Utility Methods ---

    def get_email_credentials(self):
        if self.credentials["email"] and self.credentials["password"]:
            return True
        
        email = simpledialog.askstring("Email Setup", "Enter the sender's Gmail address:")
        password = simpledialog.askstring("Email Setup", "Enter the sender's Gmail App Password:", show='*')
        
        if email and password:
            self.credentials["email"] = email
            self.credentials["password"] = password
            self.log_action(f"Email credentials configured for {email}.")
            return True
        else:
            messagebox.showwarning("Setup Incomplete", "Email credentials are required to proceed.")
            return False

    def send_email(self, subject, body, recipient):
        msg = f"Subject: {subject}\n\n{body}"
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(self.credentials["email"], self.credentials["password"])
            server.sendmail(self.credentials["email"], recipient, msg)
            server.quit()
            self.log_action(f"2FA code successfully sent to {recipient}.")
            return True
        except Exception as e:
            self.log_action(f"ERROR: Failed to send email: {e}")
            messagebox.showerror("Email Error", f"Failed to send email. Check credentials and connection.\nError: {e}")
            return False

    def log_action(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        
        # Write to file
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
            
        # Update GUI viewer
        self.log_viewer.config(state='normal')
        self.log_viewer.insert(tk.END, log_entry)
        self.log_viewer.see(tk.END) # Auto-scroll
        self.log_viewer.config(state='disabled')

    def update_dashboard_status(self, usb_text, usb_color, scan_text, scan_color):
        self.usb_status_label.config(text=usb_text, fg=usb_color)
        self.scanner_status_label.config(text=scan_text, fg=scan_color)

    def generate_otp(self, length=6):
        return "".join(random.choices(string.digits, k=length))
        
    # --- Drive Monitoring and Scanning (Threading) ---

    def start_drive_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            thread = threading.Thread(target=self.monitor_drives_thread, daemon=True)
            thread.start()
            self.process_drive_queue()

    def monitor_drives_thread(self):
        initial_drives = set(self.get_available_drives())
        while self.is_monitoring:
            time.sleep(3)
            current_drives = set(self.get_available_drives())
            new_drives = current_drives - initial_drives
            for drive in new_drives:
                self.log_action(f"New drive detected: {drive}")
                self.drive_queue.put(drive)
            initial_drives = current_drives

    def process_drive_queue(self):
        if not self.is_monitoring:
            return
        try:
            drive_to_scan = self.drive_queue.get_nowait()
            scan_thread = threading.Thread(target=self.scan_drive_thread, args=(drive_to_scan,), daemon=True)
            scan_thread.start()
        except queue.Empty:
            pass
        finally:
            self.root.after(2000, self.process_drive_queue)
            
    def scan_drive_thread(self, drive_letter):
        self.log_action(f"Starting scan on drive {drive_letter}")
        self.update_dashboard_status("USB Ports: ENABLED", "green", f"Scanner: SCANNING {drive_letter}", "cyan")
        
        threats_found = 0
        for root_dir, _, files in os.walk(drive_letter):
            for file in files:
                file_path = os.path.join(root_dir, file)
                self.log_action(f"Scanning: {os.path.basename(file_path)}")
                
                if VT_API_KEY == "8b5023f70aca9a89172347f1c99f65f06eeda209b40547025a1d480500c073bf":
                    self.log_action(" VirusTotal API key is set. ")
                    self.update_dashboard_status("USB Ports: ENABLED", "green", "Scanner:", "green")
                    return

                try:
                    file_hash = self.get_file_hash(file_path)
                    if file_hash:
                        # IMPORTANT: Free API is limited to 4 requests per minute.
                        time.sleep(16) 
                        detections = self.check_virustotal(file_hash)
                        if detections > 0:
                            threats_found += 1
                            self.log_action(f"THREAT DETECTED: {file_path} ({detections} detections)")
                            self.send_threat_alert(file_path, detections)
                            messagebox.showwarning("Threat Detected!", f"Malicious file found:\n\n{file_path}\n\nDetections: {detections}")
                except Exception as e:
                    self.log_action(f"ERROR scanning file {file_path}: {e}")

        self.log_action(f"Scan of {drive_letter} complete. Threats found: {threats_found}.")
        if threats_found > 0:
            self.update_dashboard_status("USB Ports: ENABLED", "green", f"Scanner: THREATS FOUND!", "red")
        else:
            self.update_dashboard_status("USB Ports: ENABLED", "green", f"Scanner: MONITORING", "orange")

    def get_file_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return None

    def check_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()['data']['attributes']['last_analysis_stats']['malicious']
            return 0
        except requests.RequestException:
            return -1 # Indicates an error

    def send_threat_alert(self, filepath, detections):
        subject = "⚠️ SentinelUSB: Malware Alert!"
        body = (f"A malicious file was detected on a connected USB drive.\n\n"
                f"File Path: {filepath}\n"
                f"Detections: {detections}\n"
                f"Timestamp: {datetime.now()}\n\n"
                f"Please investigate immediately.")
        self.send_email(subject, body, self.credentials['email'])

    @staticmethod
    def get_available_drives():
        return [f"{chr(c)}:\\" for c in range(ord('A'), ord('Z') + 1) if os.path.exists(f"{chr(c)}:\\")]


if __name__ == "__main__":
    # Ensure the script is run with administrator privileges
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        messagebox.showerror("Administrator Required", "This application requires administrator privileges to manage USB ports. Please restart as an administrator.")
        sys.exit()

    root = tk.Tk()
    app = SentinelApp(root)
    root.mainloop()