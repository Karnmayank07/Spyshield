# Spyshield
## Description

**Keylogger & Network Detector** is a Python-based security tool that detects and terminates potential keyloggers and suspicious network activity. It scans running processes for known **keylogger-related keywords** and monitors **active network connections** for unusual behavior. The script ensures that critical system processes are not accidentally terminated and logs all detections in `detection.log`. Users are prompted before terminating any flagged process. This tool helps enhance system security by identifying hidden threats efficiently. 

## Features 🚀
✔ Detects keyloggers using suspicious keywords  
✔ Monitors network activity for unusual connections  
✔ Provides option to terminate malicious processes  
✔ Logs all detections in `detection.log 


### **🛠️ Installation & Setup (Local Machine)**  

#### **1️⃣ Prerequisites**  
Ensure you have **Python 3.x** installed. You can check by running:  
```sh
python --version
```
If Python is not installed, download it from [python.org](https://www.python.org/downloads/).  

---

#### **2️⃣ Clone the Repository** (or Download the Code)  
```sh
git clone https://github.com/Karnmayank07/Spyshield
cd SpyShield
```
Alternatively, you can **download the ZIP** from GitHub and extract it.  

---

### **3️⃣ Install Required Dependencies**  
This script requires `psutil` for process and network monitoring. Install it using:  
```sh
pip install psutil
```

---

#### **4️⃣ Run the Script**  
Execute the script using:  
```sh
python main.py
```
It will start scanning for **suspicious processes and network activity**. If anything suspicious is found, the tool will prompt you to terminate it.  

---

