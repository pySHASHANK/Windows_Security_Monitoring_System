import win32evtlog
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import time
import threading
import tkinter as tk
import json
from tkinter import ttk
import os
import ctypes
import cv2
import datetime
import ctypes
import pystray
from PIL import Image, ImageDraw

# ----------------------------------------------------
# CONFIG
# ----------------------------------------------------
import sys
if getattr(sys, 'frozen', False):
    app_path = os.path.dirname(sys.executable)
else:
    app_path = os.path.dirname(os.path.abspath(__file__))

secrets_path = os.path.join(app_path, "secrets.json")
if not os.path.exists(secrets_path):
    secrets_path = os.path.join(app_path, "..", "secrets.json")

try:
    with open(secrets_path, "r") as f:
        _secrets = json.load(f)
        EMAIL_ADDRESS = _secrets.get("EMAIL_ADDRESS", "shashankpaandey@gmail.com")
        EMAIL_PASSWORD = _secrets.get("EMAIL_PASSWORD", "")
except Exception as e:
    EMAIL_ADDRESS = "shashankpaandey@gmail.com"
    EMAIL_PASSWORD = ""

TO_EMAIL = EMAIL_ADDRESS

failed_attempts = 0
last_failed_time = 0  # time of last failed attempt
running = True
last_record = 0
last_email_time = 0  # for cooldown

# ----------------------------------------------------
# LOGON TYPE MAP
# ----------------------------------------------------
def get_logon_type_name(code):
    mapping = {
        "2": "Local",
        "3": "Network",
        "10": "Remote Desktop"
    }
    return mapping.get(str(code), "Unknown")

# ----------------------------------------------------
# CAPTURE INTRUDER
# ----------------------------------------------------
def capture_intruder():
    try:
        # Using cv2.CAP_DSHOW for better Windows compatibility
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

        if not cap.isOpened():
            print("❌ Camera not accessible")
            return None

        # Warm up the camera to adjust lighting/focus
        for _ in range(5):
            cap.read()
            time.sleep(0.1)

        ret, frame = cap.read()
        cap.release()

        if ret:
            filename = f"intruder_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            cv2.imwrite(filename, frame)
            print(f"📸 Captured: {filename}")
            return filename
        else:
            print("❌ Failed to grab frame")
            return None

    except Exception as e:
        print("Camera error:", e)
        return None

# ----------------------------------------------------
# EMAIL ALERT
# ----------------------------------------------------
def send_email_alert(username, logon_type, timestamp, image_path=None):
    global last_email_time

    # Cooldown removed so every failed attempt is logged immediately
    # (Especially important for capturing the 3rd attempt with image)

    message = f"""
⚠ Unauthorized Login Attempt Detected!

User: {username}
Logon Type: {logon_type}
Time: {timestamp}
"""

    if image_path:
        msg = MIMEMultipart()
        msg.attach(MIMEText(message, 'plain'))
    else:
        msg = MIMEText(message)

    msg["Subject"] = "❗ Security Alert"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = TO_EMAIL

    # Attach image if present
    if image_path and os.path.exists(image_path):
        try:
            with open(image_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {os.path.basename(image_path)}",
            )
            msg.attach(part)
        except Exception as e:
            print("❌ Could not attach image:", e)

    try:
        if not EMAIL_PASSWORD:
            raise ValueError("Password missing in secrets.json")

        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)

        print("📧 Email Sent!")
        root.after(0, lambda: status_var.set("Email Alert Sent!"))
        last_email_time = time.time()

    except Exception as e:
        print("❌ Email Failed:", e)
        # Display short error in the GUI System Status card
        root.after(0, lambda err=e: status_var.set(f"Email Error: {str(err)[:25]}"))

# ----------------------------------------------------
# ADD LOG TO UI
# ----------------------------------------------------
def add_log(username, logon_type, timestamp):
    count = len(tree.get_children())
    tag = 'evenrow' if count % 2 == 0 else 'oddrow'
    tree.insert("", 0, values=(username, logon_type, timestamp), tags=(tag,))
    
    try:
        attempts_var.set(str(failed_attempts))
        last_time_var.set(timestamp)
        if failed_attempts >= 3:
            status_var.set("🚨 BREACH")
            sys_status_label.config(fg="#ff1744")
        else:
            status_var.set("Active")
            sys_status_label.config(fg="#00E676")
    except Exception:
        pass

# ----------------------------------------------------
# MONITOR FUNCTION
# ----------------------------------------------------
def monitor_failed_logins():
    global running, last_record, failed_attempts, last_failed_time

    if not ctypes.windll.shell32.IsUserAnAdmin():
        root.after(0, add_log, "SYSTEM", "ERROR", "Run as Administrator")
        return

    logs = None  # 🔥 keep handle persistent

    while running:
        try:
            # Reopen each time to poll for newest events
            logs = win32evtlog.OpenEventLog(None, "Security")

            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(logs, flags, 0)

            if events:
                if last_record == 0:
                    last_record = events[0].RecordNumber

                newest_record = events[0].RecordNumber

                for event in events:
                    if event.RecordNumber <= last_record:
                        break

                    if event.EventID == 4625:
                        current_time = time.time()
                        # Reset if more than 5 minutes (300 seconds) since last failure
                        if last_failed_time > 0 and (current_time - last_failed_time > 300):
                            failed_attempts = 0
                            
                        failed_attempts += 1
                        last_failed_time = current_time

                        data = event.StringInserts
                        username = data[5] if data and len(data) > 5 else "Unknown"
                        logon_raw = data[8] if data and len(data) > 8 else "Unknown"
                        logon_type = get_logon_type_name(logon_raw)
                        timestamp = event.TimeGenerated.Format()

                        root.after(0, add_log, username, logon_type, timestamp)

                        # 📸 3rd attempt → capture
                        if failed_attempts == 3:
                            image_path = capture_intruder()

                            threading.Thread(
                                target=send_email_alert,
                                args=(username, logon_type, timestamp, image_path),
                                daemon=True
                            ).start()

                        # 💥 4th attempt → shut down system
                        elif failed_attempts >= 4:
                            ctypes.windll.user32.LockWorkStation()
                            failed_attempts = 0

                if newest_record > last_record:
                    last_record = newest_record

            win32evtlog.CloseEventLog(logs)
            logs = None

            time.sleep(5)

        except Exception as e:
            print("⚠ Monitor Error:", e)
            root.after(0, add_log, "ERROR", "Monitor", str(e))
            if logs:
                try:
                    win32evtlog.CloseEventLog(logs)
                except Exception:
                    pass
                logs = None

            time.sleep(5)

# ----------------------------------------------------
# GUI SETUP
# ----------------------------------------------------
root = tk.Tk()
root.title("Windows Security Monitor")
root.geometry("1000x650")
root.configure(bg="#0B0F19")
root.minsize(800, 500)

attempts_var = tk.StringVar(value="0")
last_time_var = tk.StringVar(value="N/A")
status_var = tk.StringVar(value="Active")

style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", 
    background="#1A2234", 
    foreground="#E2E8F0", 
    rowheight=35, 
    fieldbackground="#1A2234",
    borderwidth=0,
    font=("Segoe UI", 10)
)
style.configure("Treeview.Heading", 
    background="#0F172A", 
    foreground="#00E676", 
    borderwidth=0,
    font=("Segoe UI", 11, "bold")
)
style.map("Treeview", background=[('selected', '#2563EB')])

main_frame = tk.Frame(root, bg="#0B0F19")
main_frame.pack(fill="both", expand=True)

# Sidebar
sidebar = tk.Frame(main_frame, bg="#131B2F", width=200)
sidebar.pack(side="left", fill="y", pady=10, padx=(10, 0))

def on_enter(e): e.widget['background'] = '#1E293B'
def on_leave(e): e.widget['background'] = '#131B2F'

def sidebar_click(event):
    from tkinter import messagebox
    messagebox.showinfo("Coming Soon", "This feature is currently under development.")

tk.Label(sidebar, text="🛡️ WSM", font=("Segoe UI", 24, "bold"), fg="#00E676", bg="#131B2F").pack(pady=30)
for menu in ["Dashboard", "Logs", "Settings"]:
    lbl = tk.Label(sidebar, text=f"   {menu}", font=("Segoe UI", 12), fg="#E2E8F0", bg="#131B2F", anchor="w", padx=20, pady=15, cursor="hand2")
    lbl.pack(fill="x")
    lbl.bind("<Enter>", on_enter)
    lbl.bind("<Leave>", on_leave)
    lbl.bind("<Button-1>", sidebar_click)

# Content
content = tk.Frame(main_frame, bg="#0B0F19")
content.pack(side="right", fill="both", expand=True, padx=20, pady=10)

# Header
header = tk.Frame(content, bg="#0B0F19")
header.pack(fill="x", pady=10)
tk.Label(header, text="Windows Security Monitor", font=("Segoe UI", 20, "bold"), fg="#F8FAFC", bg="#0B0F19").pack(side="left")

status_frame = tk.Frame(header, bg="#0B0F19")
status_frame.pack(side="right")
status_dot = tk.Label(status_frame, text="●", font=("Segoe UI", 16), fg="#00E676", bg="#0B0F19")
status_dot.pack(side="left", padx=5)
status_text = tk.Label(status_frame, text="Running", font=("Segoe UI", 12), fg="#94A3B8", bg="#0B0F19")
status_text.pack(side="left")

# Dashboard Cards
cards_frame = tk.Frame(content, bg="#0B0F19")
cards_frame.pack(fill="x", pady=15)
cards_frame.columnconfigure((0,1,2), weight=1)

def create_card(parent, title, var, col, color="#00E676"):
    f = tk.Frame(parent, bg="#1A2234", bd=0, highlightbackground="#334155", highlightthickness=1)
    f.grid(row=0, column=col, sticky="nsew", padx=10)
    tk.Label(f, text=title, font=("Segoe UI", 11), fg="#94A3B8", bg="#1A2234").pack(anchor="w", padx=15, pady=(15,0))
    lbl = tk.Label(f, textvariable=var, font=("Segoe UI", 22, "bold"), fg=color, bg="#1A2234")
    lbl.pack(anchor="w", padx=15, pady=(5,15))
    return lbl

create_card(cards_frame, "Total Failed Attempts", attempts_var, 0, "#00E676")
create_card(cards_frame, "Last Attempt Time", last_time_var, 1, "#E2E8F0")
sys_status_label = create_card(cards_frame, "System Status", status_var, 2, "#00E676")

# Buttons (Packed at bottom FIRST to prevent cutoff)
btn_frame = tk.Frame(content, bg="#0B0F19")
btn_frame.pack(side="bottom", fill="x", pady=10, padx=10)

# Table (Packed AFTER buttons with expand=True)
table_frame = tk.Frame(content, bg="#1A2234", highlightbackground="#334155", highlightthickness=1)
table_frame.pack(side="top", fill="both", expand=True, pady=10, padx=10)

cols = ("Username", "Logon Type", "Time")
tree = ttk.Treeview(table_frame, columns=cols, show="headings")
for col in cols:
    tree.heading(col, text=col.upper())
    tree.column(col, width=200, anchor="center")

tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
tree.tag_configure('oddrow', background="#1A2234")
tree.tag_configure('evenrow', background="#222B45")
scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y", pady=5)

def toggle_monitoring():
    global running
    if running:
        running = False
        status_dot.config(fg="#ff1744")
        status_text.config(text="Stopped")
        btn_start_stop.config(text="▶ Start Monitoring", bg="#1A2234")
        status_var.set("Stopped")
        sys_status_label.config(fg="#ff1744")
    else:
        running = True
        status_dot.config(fg="#00E676")
        status_text.config(text="Running")
        btn_start_stop.config(text="⏹ Stop Monitoring", bg="#ff1744")
        status_var.set("Active")
        sys_status_label.config(fg="#00E676")
        threading.Thread(target=monitor_failed_logins, daemon=True).start()

def clear_logs():
    for item in tree.get_children():
        tree.delete(item)

def export_logs():
    import csv
    try:
        with open("security_logs.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Username", "Logon Type", "Time"])
            for item in tree.get_children():
                writer.writerow(tree.item(item)['values'])
        status_var.set("Logs Exported")
    except Exception as e:
        status_var.set("Export Error")

def btn_hover(e): e.widget['background'] = '#334155'
def btn_leave(e, c): e.widget['background'] = c

btn_start_stop = tk.Button(btn_frame, text="⏹ Stop Monitoring", font=("Segoe UI", 10, "bold"), fg="white", bg="#ff1744", bd=0, padx=15, pady=8, cursor="hand2", command=toggle_monitoring)
btn_start_stop.pack(side="left", padx=5)

b1 = tk.Button(btn_frame, text="🗑 Clear Logs", font=("Segoe UI", 10, "bold"), fg="white", bg="#1A2234", bd=0, padx=15, pady=8, cursor="hand2", command=clear_logs)
b1.pack(side="left", padx=5)
b1.bind("<Enter>", btn_hover)
b1.bind("<Leave>", lambda e: btn_leave(e, '#1A2234'))

b2 = tk.Button(btn_frame, text="💾 Export Logs", font=("Segoe UI", 10, "bold"), fg="white", bg="#1A2234", bd=0, padx=15, pady=8, cursor="hand2", command=export_logs)
b2.pack(side="right", padx=5)
b2.bind("<Enter>", btn_hover)
b2.bind("<Leave>", lambda e: btn_leave(e, '#1A2234'))

# Footer
tk.Label(content, text="Real-time Windows Intrusion Detection System", font=("Segoe UI", 9), fg="#475569", bg="#0B0F19").pack(side="bottom", pady=5)

# ----------------------------------------------------
# TRAY ICON
# ----------------------------------------------------
def create_icon():
    image = Image.new('RGBA', (64, 64), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((8, 8, 56, 56), fill=(225, 29, 72))
    draw.ellipse((16, 16, 48, 48), outline=(255, 255, 255), width=4)
    return image

def show_window(icon, item):
    root.after(0, root.deiconify)

def exit_app(icon, item):
    global running
    running = False
    icon.stop()
    root.after(0, root.destroy)

def run_tray():
    icon = pystray.Icon("SecurityMonitor", create_icon(), "Security Monitor", menu=pystray.Menu(pystray.MenuItem("Open", show_window), pystray.MenuItem("Exit", exit_app)))
    icon.run()

# ----------------------------------------------------
# MINIMIZE TO TRAY
# ----------------------------------------------------
def minimize_to_tray():
    root.withdraw()

root.protocol("WM_DELETE_WINDOW", minimize_to_tray)

# ----------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------
threading.Thread(target=monitor_failed_logins, daemon=True).start()
threading.Thread(target=run_tray, daemon=True).start()

# Application starts minimized in tray
root.withdraw()
root.mainloop()