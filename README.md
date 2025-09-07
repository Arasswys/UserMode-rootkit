# 🕵️ Rootkit Analysis

## 🏷️ Type
- 🌀 **Ring 3 (User-mode) Rootkit**
- 🔀 **Hybrid:** Spy + Destructive (collects information + corrupts the system)
- 🔑 **Encrypted payload support** (Fernet + Base64)

## ⚙️ Features
- 💻 Gathering system information *(username, computer name, IP, UUID, OS version)*
- 📊 Retrieving hardware and process information *(CPU, RAM, disk, running processes)*
- 💉 Process injection + Windows API usage
- 🔒 Persistence *(potential for injecting into startup)*
- 🕶️ Anti-forensic *(hashing, encoding, encryption)*
- 📡 C2 support *(ability to POST data to external systems)*
- 🔄 Multi-threaded background task execution
- 📦 Encrypted payload execution
- 🛠 Attempts to interfere with Windows services and cmd.exe
- 💥 Destructive behavior that may disrupt system stability

## ☠️ Danger Level
- 👁️ Not only **spyware**, but also **destructive rootkit**
- 📌 **Persistence** and **remote control** capabilities
- 🧩 **Encryption** has the potential to evade antiviruses
- ⚡ **Display bugs** and **service disruptions** were observed during testing
- 🚨 Reaches **advanced rootkit** level upon completion

---

⚠️ **WARNING**
This project is for **education and training purposes only For research purposes only**. 🔬
Should not be used in real systems ❌💻
