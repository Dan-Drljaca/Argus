from scanner import get_local_ip, scan_ports, get_wifi_security, get_wifi_password, analyze_password_strength
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt

#setting up Quality of life 
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.title("Argus Net Protector")
app.geometry("800x700") # just for it to look better see if i need to change resolution

# header
header = ctk.CTkLabel(app, text="Argus Net Protector", font=ctk.CTkFont(size=24, weight="bold"))
header.pack(pady=20)
open_count = 0
closed_count = 0

#run button
def run_scan():
    ip = get_local_ip()
    ip_var.set(f"Local IP: {ip}")

    # portscan
    results = scan_ports(ip)
    for row in port_results.get_children():
        port_results.delete(row)
    for host, data in results.items():
        for proto, ports in data['protocols'].items():
            for port, state in ports.items():
                tag = "open" if state.lower() == "open" else "closed"
                port_results.insert("", "end", values=(host, proto, port, state), tags=(tag,))
                if tag =="open":
                    open_count += 1
                else:
                    closed_count += 1
    # wifi sec info
    security = get_wifi_security()
    if security:
        sec_lower = security.lower()
        if "wep" in sec_lower:
            wifi_msg = f"Wi-Fi Security: {security}\n❌ WEP is outdated and insecure. Please upgrade your router."
        elif "wpa3" in sec_lower:
            wifi_msg = f"Wi-Fi Security: {security}\n🔒 You're using WPA3 – the newest and most secure protocol."
        elif "wpa2" in sec_lower:
            wifi_msg = f"Wi-Fi Security: {security}\n✅ WPA2 is secure, but consider upgrading to WPA3 if possible."
        else:
            wifi_msg = f"Wi-Fi Security: {security}\n⚠️ Security type detected, but not recognized for assessment."
    else:
        wifi_msg = "⚠️ Could not determine Wi-Fi security type."
    wifi_sec_var.set(wifi_msg)
    # Psswd strentgth
    pwd = get_wifi_password()
    strength_text = analyze_password_strength(pwd)
    pwd_strength_var.set(strength_text)
    if "Strong" in strength_text:
        pwd_strength_label.configure(bg_color="#CCFFCC")
    elif "Moderate" in strength_text:
        pwd_strength_label.configure(bg_color="#FFFFCC")
    else:
        pwd_strength_label.configure(bg_color="#FFCCCC")

scan_button = ctk.CTkButton(app, text="Run Scan", command=run_scan)
scan_button.pack(pady=10)




def show_port_chart(open_count, closed_count):
    total = open_count + closed_count
    if total == 0:
        print("no ports scanned or all states unknow - skipping chart.")
        return #nonthing to plot or due to error so please fix future dan
    
    
    
    labels = ['Open', 'Closed']
    sizes = [open_count, closed_count]
    colors = ['#FF6666', '#66FF66']

    plt.figure(figsize=(4, 4))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title("Port Scan Summary")
    plt.axis('equal')
    plt.tight_layout()
    plt.show


#after filling the table
show_port_chart(open_count, closed_count)

# --- IP Display ---
ip_var = tk.StringVar()
ip_label = ctk.CTkLabel(app, textvariable=ip_var, font=ctk.CTkFont(size=14))
ip_label.pack(pady=5)

# --- Wi-Fi Security Display ---
wifi_sec_var = tk.StringVar()
wifi_sec_label = ctk.CTkLabel(app, textvariable=wifi_sec_var, wraplength=700, justify="center")
wifi_sec_label.pack(pady=5)

# --- Password Strength Display ---
pwd_strength_var = tk.StringVar()
pwd_strength_label = ctk.CTkLabel(app, textvariable=pwd_strength_var, wraplength=700, justify="center")
pwd_strength_label.pack(pady=5)

# --- Treeview (Port Scan Table) ---
port_results_label = ctk.CTkLabel(app, text="Port Scan Results:", font=ctk.CTkFont(size=16, weight="bold"))
port_results_label.pack(pady=10)

tree_frame = ctk.CTkFrame(app)
tree_frame.pack(pady=5)

columns = ("host", "protocol", "port", "state")
port_results = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
for col in columns:
    port_results.heading(col, text=col.title())
    port_results.column(col, width=150, anchor="center")
port_results.pack()

# Add tag-based color coding
port_results.tag_configure("open", background="#FFCCCC")   # Red
port_results.tag_configure("closed", background="#CCFFCC") # Green

# --- Launch App ---
app.mainloop()