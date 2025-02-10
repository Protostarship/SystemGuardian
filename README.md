# SystemGuardian - Comprehensive Documentation

## 📌 Overview
**SystemGuardian** is a high-performance Windows service designed for **real-time system monitoring, failure prevention, and automated recovery**. It ensures system stability by tracking **drivers, services, registry changes, and system integrity**, preventing potential failures, crashes, and unauthorized modifications.

## 📥 Installation & Setup
### 1️⃣ Prerequisites
- Windows **10/11**, Windows **Insider Preview** or **Windows Server 2016+**
- Administrator privileges

### 2️⃣ Install SystemGuardian
To install the SystemGuardian service, open a command prompt with **Administrator privileges** and run:
```powershell
sc create SystemGuardian binPath= "C:\\Path\\To\\SystemGuardian.exe" start= auto
```
This registers the service in Windows and configures it to start automatically on system boot.

### 3️⃣ Start the Service
To manually start the service, run:
```powershell
sc start SystemGuardian
```

### 4️⃣ Stop or Restart the Service
If you need to stop or restart the service, use:
```powershell
sc stop SystemGuardian
sc start SystemGuardian
```

### 5️⃣ Uninstall SystemGuardian
To remove the service completely from the system, execute:
```powershell
sc delete SystemGuardian
```

---

## ⚙️ How It Works
### 🛡️ **Core Features**
✅ **Real-time System Monitoring** - Watches **drivers, registry keys, and services** for changes.
✅ **Automated Recovery**  - Restores **services, drivers, and registry keys** from backups.
✅ **Integrity Protection** - Uses **SHA-256 file hashing** to detect modifications.
✅ **Driver Verification** - Blocks **unsigned/unverified drivers**.
✅ **Crash Prevention** - Detects system crashes and **creates restore points automatically**.
✅ **Event Logging & Alerts** - Logs system failures and can **notify administrators**.

### 🔄 **Recovery Process**
1. **Detect** an issue (e.g., service failure, driver corruption).
2. **Backup** registry and critical components.
3. **Attempt Auto-Recovery**:
   - **Restart failed services**.
   - **Restore corrupted drivers from backups**.
   - **Rollback registry keys if altered**.
4. **Notify the user** if intervention is required.

---

## 🔧 Configuration Management
### 🔹 Configuration File Location
SystemGuardian uses a configuration file to define which system components should be monitored. The default configuration file is located at:
```plaintext
C:\ProgramData\SystemGuardian\config.json
```

### 🔹 What if the Configuration File is Missing?
- If the configuration file **does not exist**, the service will automatically generate a default configuration with standard monitoring settings.
- Users can manually create a configuration file in the same directory to customize monitoring.

### 🔹 Example Configuration File
```json
{
    "MonitorDrivers": true,
    "MonitorServices": true,
    "MonitorRegistry": true,
    "CriticalPaths": [
        "C:\\Windows\\System32\\drivers",
        "C:\\Windows\\System32"
    ]
}
```

### 🔹 Modifying Configuration Settings
To modify the configuration:
1. Open `C:\ProgramData\SystemGuardian\config.json` with a text editor.
2. Adjust monitoring preferences as needed.
3. Restart the service for changes to take effect:
   ```powershell
   sc stop SystemGuardian
   sc start SystemGuardian
   ```

### 🔹 Enable Debug Logging
To enable **verbose logging** for troubleshooting:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SystemGuardian" -Name "DebugLogging" -Value 1 -PropertyType DWord -Force
```

---

## 📜 Service Management
### 🔹 Checking Service Status
To check if the service is running:
```powershell
sc query SystemGuardian
```

### 🔹 Viewing Logs
- Logs are saved in: `C:\ProgramData\SystemGuardian\Logs\`
- Use Notepad or PowerShell to view logs:
  ```powershell
  Get-Content C:\ProgramData\SystemGuardian\Logs\latest.log -Tail 50 -Wait
  ```

### 🔹 Manually Recovering a Component
If a monitored component fails and SystemGuardian does not auto-recover it, you can manually recover it by running:
```powershell
SystemGuardian.exe /recover "ComponentName"
```

### 🔹 Restoring Registry from Backup
```powershell
reg import C:\ProgramData\SystemGuardian\registry_backup.reg
```

---

## 🔍 Considerations & Best Practices
1️⃣ **Always Run as Administrator** - SystemGuardian requires administrative privileges to monitor and recover system components.

2️⃣ **Regularly Check Logs** - Monitor logs in `C:\ProgramData\SystemGuardian\Logs\` to detect unusual activity.

3️⃣ **Backups are Critical** - Ensure that **registry and system file backups** are created regularly.

4️⃣ **Avoid Modifying System Files Manually** - If you need to restore a system file, use the SystemGuardian recovery process.

5️⃣ **Verify Driver & Service Integrity** - Before installing third-party drivers, use SystemGuardian's integrity verification features to ensure they are safe.

---

## ❓ FAQ & Troubleshooting
### ❓ How do I check service status?
```powershell
sc query SystemGuardian
```

### ❓ Where are logs stored?
- Logs are saved in: `C:\ProgramData\SystemGuardian\Logs\`

### ❓ How do I manually recover a component?
- Open a command prompt as **Administrator**.
- Run:
```powershell
SystemGuardian.exe /recover "ComponentName"
```

### ❓ What happens if a driver is blocked?
- SystemGuardian will **isolate the driver**, preventing it from running.
- The user will be notified and can **choose to restore or permanently block** it.

---

## 📞 Support
For assistance, open an issue on our **GitHub repository** or contact support at: `relay.arbiter303@gmail.com`.

---

**© 2025 SystemGuardian | All Rights Reserved**
