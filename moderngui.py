#attempt one at modern gui 
from scanner import get_local_ip, scan_ports, get_wifi_security, get_wifi_password, analyze_password_strength, get_ssid
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as tb
import matplotlib.pyplot as plt
import time
from report_generator import generate_report
from tkinter import filedialog



#quality of life 
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Argus Net Protector")
app.geometry("800x700") # size at start
app.resizable(True,True) #for lack of better words this makes the application more dynamic and moderns than compared app.geometry(000x000) 

#font was origianlly 24 
header = ctk.CTkLabel(app, text="Argus Net Protector", font=ctk.CTkFont(size=28, weight="bold"))
header.grid(row=0, column=0, columnspan=2, pady=20)

#status bar 
scan_status_var = ctk.StringVar(value="Status: Idle")
scan_status_label = ctk.CTkLabel(app, textvariable=scan_status_var, font=ctk.CTkFont(size=16))
scan_status_label.grid(row=1, column=0, columnspan=2, pady=(0,5), sticky="ew")
scan_status_var.set("Scan Complete")
scan_status_label.configure(text_color="green")

#the actual bar
scan_progress = ctk.CTkProgressBar(app, width=600)
scan_progress.grid(row=2, column=0, columnspan=2, pady=(0,10), sticky="ew")
scan_progress.set(0)

#left frame idividual port status, 
left_frame= ctk.CTkFrame(app, corner_radius=10)
left_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=10)
left_frame.update_idletasks()
left_frame.configure(width=440)
#key thing here is font
# Font for port scan results was originally 16 
port_results_label = ctk.CTkLabel(left_frame, text="Port Scan Results", font=ctk.CTkFont(size=24,weight="bold")) 
port_results_label.grid(row=0, column=0, sticky="w",pady=(0,5))

#lf indiv port labels 
port_to_scan = [22, 23, 25, 80, 3389]

#dic to hold labels so mee-sa can update later (jar-jar)
port_labels = {}


#CREED labels for each port
#creed is a great brand anyways font was originally 14 changing it becasue its to small
for i, port in enumerate(port_to_scan, start=1):
    lbl = ctk.CTkLabel(left_frame, text=f"Port {port}: unknown", font=ctk.CTkFont(size=18))
    lbl.grid(row=i, column=0, sticky="w", pady=2)
    port_labels[port] = lbl #store lbl for updates 

#wifi sec lbl
#wifi sec lbl's font was originally 14
wifi_security_var = ctk.StringVar(value="Wi-Fi Security: Unknown")
wifi_security_label = ctk.CTkLabel(left_frame, textvariable=wifi_security_var, font=ctk.CTkFont(size=18))
wifi_security_label.grid(row=len(port_to_scan)+1, column=0, sticky="w")

#pwd str lbl
#font was originally 14 
pwd_strength_var = ctk.StringVar(value="Password Strength: Unknown")
pwd_strength_label = ctk.CTkLabel(left_frame, textvariable=pwd_strength_var, font=ctk.CTkFont(size=18))
pwd_strength_label.grid(row=len(port_to_scan)+2, column=0, sticky="w")



#stretchy 
left_frame.grid_rowconfigure(len(port_to_scan)+3, weight=1)
left_frame.grid_columnconfigure(0,weight=1)




#right frame graph score
right_frame = ctk.CTkFrame(app, corner_radius=10)
right_frame.grid(row=3, column=1, sticky="nsew", padx=10, pady=10)
right_frame.update_idletasks()
right_frame.configure(width=320)

#cneter hortiz
right_frame.grid_columnconfigure(0, weight=1)


#lbls and progress bar
#font was originally 18 but too small 
score_label = ctk.CTkLabel(right_frame, text="Your Network Security Score", font=("Arial", 24), anchor="center")
score_label.grid(row=0,column=0, pady=(0,5), sticky="n")

score_var = ctk.StringVar(value="0%")
score_display = ctk.CTkLabel(
    right_frame,
    textvariable=score_var,
    font=ctk.CTkFont(size=48, weight="bold"),
    text_color="#007ACC",
    anchor="center"
)
score_display.grid(row=1, column=0, pady=(0,5), sticky="n")

progress_score = ctk.CTkProgressBar(right_frame,width=200)
progress_score.grid(row=2, column=0, pady=(0,5), sticky="n")
progress_score.set(0)

# passwords scoring 
def update_password_strength(score: int):
    if score >= 80:
        color = "green"
    elif 50 <= score < 80:
        color = "yellow"
    else:
        color = "red"
    pwd_strength_var.set(f"Password Strength: {score}%")
    pwd_strength_label.configure(text_color=color)













#colums 
app.grid_columnconfigure(0, weight=11)
app.grid_columnconfigure(1, weight=9)

#rows
app.grid_rowconfigure(0, weight=0) #header
app.grid_rowconfigure(1, weight=0) #scan status
app.grid_rowconfigure(2, weight=0) #scan progress
app.grid_rowconfigure(3, weight=1) #main frames


# Connecting the dynamic data to the GUI 

#ports 
def update_ports():
    for port in port_to_scan:
        port_labels[port].configure(text=f"Port {port}: unknown", text_color="black")

    local_ip = get_local_ip()
    port_string = ",".join(str(p)for p in port_to_scan)
    results = scan_ports(local_ip, port_string)

    if not results:
        print("No scan results")
        return
    
    first_host = list(results.keys())[0]
    tcp_ports = results[first_host]["protocols"].get("tcp", {})

    total_ports = len(port_to_scan)
    for i, port in enumerate(port_to_scan, start=1):
        status = tcp_ports.get(port, "unknown")
        color = "red" if status.lower() == "open" else "green"  # closed = green, open = red
        port_labels[port].configure(text=f"Port {port}: {status}", text_color=color)
        

        scan_status_var.set(f"Scanning... {i}/{total_ports} ports")
        scan_progress.set(i / total_ports)
        app.update_idletasks()  # refresh GUI

    scan_status_var.set("Scan Complete")
    scan_progress.set(1)
    app.update_idletasks()
    time.sleep(0.1)


#wifi sec 

def update_wifi_security():
    security = get_wifi_security()
    wifi_security_var.set(f"Wi-Fi Security: {security}")

#pwd 
def update_password():
    password = get_wifi_password()
    strength = analyze_password_strength(password)
    update_password_strength(strength)

# ntw score
def update_network_score():
    password = get_wifi_password()
    strength = analyze_password_strength(password)
    local_ip = get_local_ip()
    port_string = ",".join(str(p)for p in port_to_scan)
    ports = scan_ports(local_ip, port_string)
    
    if not ports:
        print("No scan results")
        return
    
    first_host = list(ports.keys())[0]
    tcp_ports = ports[first_host]["protocols"].get("tcp", {})
    open_ports = sum(1 for status in tcp_ports.values() if status.lower() == "open")

    
    
    score = max(0, strength - (open_ports * 10))
    score_var.set(f"{score}%")
    progress_score.set(score/100)

#ssid lbl
#font was originally 14 
ssid_var = ctk.StringVar(value="Connected SSID: Unknown")
ssid_label = ctk.CTkLabel(left_frame, textvariable=ssid_var, font=ctk.CTkFont(size=18))
ssid_label.grid(row=len(port_to_scan)+3, column=0, sticky="w")

#funtion..update..ssid
def update_ssid():
    ssid = get_ssid() or "Unknown Network"
    ssid_var.set(f"Connected SSID: {ssid}")


#run scan button
def run_scan():
    scan_status_var.set("Starting scan...")
    scan_status_label.configure(text_color="black")
    scan_progress.set(0)
    app.update_idletasks()

    update_ports()
    update_ssid()
    update_wifi_security()
    update_password()
    update_network_score()
    scan_status_label.configure(text_color="green")  # final status green
scan_btn = ctk.CTkButton(left_frame, text="Run Scan", command=run_scan)
scan_btn.grid(row=len(port_to_scan)+4, column=0, pady=10)


#PDF report 
def generate_pdf_callback():
    #ask user where to save the PDF 
    filename = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Save Securtiy Report"
    )
    if not filename:
        return #user decided to cancel
    
    #gather data from gui
    network_name = get_ssid() or "Unknown Network"
    score = int(score_var.get().replace("%",""))
    wifi_security = wifi_security_var.get().replace("Wi-Fi Security: ", "")
    password_strength = pwd_strength_var.get().replace("Password Strength: ","")

    #build ports dict from lbls
    ports ={}
    for port, label in port_labels.items():
        status_text = label.cget("text").split(": ")[1]
        ports[port] = status_text

    #reccommmendation list 
    notes = []
    for port, status in ports.items():
        if status.lower() == "open":
            notes.append(f"Port {port} is open. Please consider closing it to enhance security.")
    if int(password_strength.replace("%","")) <80:
        notes.append("Your Wi-Fi password is weak. Recommendation: Add more unique characters, random capitalized letters, and numbers to enhance your password security. ")

    generate_report(filename, network_name, score, wifi_security, password_strength, ports, notes)


generate_button = ctk.CTkButton(right_frame, text="Generate PDF Report", command=generate_pdf_callback)
generate_button.grid(row=3, column=0, pady=10)







app.mainloop()