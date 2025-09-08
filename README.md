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

# 🕵️ Rootkit Feature Table

1️⃣ **Category: Type / Type**
- 🌀 Runs as a Ring 3 (User-mode) rootkit and manipulates system calls.
- 🔀 Hybrid: Combines Spy + Destructive features, can both collect data and disrupt the system.
- 🔑 Payloads are encrypted with Fernet + Base64 to hide from antiviruses.
- 🧩 Generates a different signature on each run with polymorphic data generation.
- 🛠 Code obfuscation is implemented, making reverse engineering difficult.
- 🕶️ Deletes or modifies logs and traces with anti-forensics techniques.
- 📡 Provides remote data transmission and control with C2 (Command & Control) support.
- 💻 Collects system information: Collects CPU, RAM, disk, operating system, and user information.
- 🧠 It runs as a memory resident and remains constantly active in the background.
- ⚡ It executes many malicious processes simultaneously with multi-thread support.
- 🪝 It can monitor and manipulate critical Windows APIs with API hooking.
- 📝 It changes file timestamps and hides traces with file time stomping.
- 📂 It hides data and makes it invisible using Alternate Data Streams (ADS).
- 🔄 It copies itself to disks and portable devices with the self-replication mechanism.
- ⏱️ It runs malicious functions with random delays with delayed execution.
- 🔒 It hides payloads and hides execution paths with environment variable manipulation.
- 🧬 It provides flexible access to the target system's libraries with dynamic API resolution.
- 💽 It injects hidden code into system processes with process hollowing and doppelgänging techniques.
- 🖥️ Executes malicious functions in target processes through Reflective DLL injection.
- 🛡️ Disguises malicious processes as safe system services through service masquarade.

2️⃣ **Category: What it can do / Impact**
- 💥 Can cause system instability and errors, and can cause application crashes.
- 🖥️ Can slow down the operating system by stopping or manipulating critical services.
- 🔌 Can disrupt the user experience by interrupting Bluetooth and other device connections.
- 📝 Can collect personal information by modifying browser and user settings.
- 🔒 Can block user access by modifying file permissions.
- 🧩 Can change browser homepage and search engine settings.
- 📂 Can evade antivirus scans by hiding files and folders.
- 🛠️ Can persist on all disks and removable devices by replicating itself.
- 🔁 It can register itself to run automatically at system startup.
- 🪝 It can bypass security software by manipulating system calls with API hooking.
- 💽 It injects malicious code into trusted processes with process hollowing.
- 🧬 It stealthily infiltrates a process with process doppelgänging and executes malicious code.
- 📝 It can execute malicious payloads in existing processes with reflective DLL injection.
- 💾 It makes data invisible with Alternative Data Streams (ADS).
- 🔄 It can replicate on all disks and connected devices with its self-replication mechanism.
- ⚡ It runs continuously in system RAM as a memory resident.
- 🕵️ It deletes logs, event logs, and system traces with anti-forensics techniques.
- 🔐 It makes antivirus detection more difficult by encrypting payloads.
- 🔨 Can infect USB and other removable media.
- 🌐 Can manage the system externally via remote control and data transfer (C2).

3️⃣ **Category: Persistence**
- 🏷️ Automatically runs in the user session by being added to the Windows Registry.
- 📅 Reruns itself at regular intervals by creating a Scheduled Task.
- 📁 Activates at every system startup by being copied to the Startup folder.
- 🧩 Runs when the user logs on with a WMI event-based trigger.
- ⏱️ Runs on restart with a cron job on Linux/Mac systems.
- ⚡ Remains constantly active in the background with the Systemd user service.
- 📝 Runs at startup by adding to the .profile or .bashrc file.
- 🔄 Copies itself to reserved areas with hidden partition write.
- 💾 It becomes invisible and persistent with Alternative Data Streams (ADS).
- 🧬 It replicates on all disks and connected devices with its self-replication mechanism.
- 🛠 It attaches itself to USB and external storage.
- 🕵️ It creates trigger mechanisms with WMI and event subscriptions.
- 🔧 It can disable the task manager and security tools.
- ⚙️ It masks system services and presents them as trusted services.
- 📝 It erases traces by changing file timestamps.
- 🔑 It makes antivirus detection more difficult with its encrypted payload.
- 📡 It enables remote reactivation with C2 commands.
- 🖥️ It runs continuously in memory and remains active even when the system is rebooted.
- 🔄 It can update its own copies and delete old copies.
- 📂 It is stored in hidden files and folders on the system.

4️⃣ **Category: Encryption / Obfuscation**
- 🔑 Encrypts all data and payloads with Fernet + Base64.
- 🕵️ Leaves no trace by encrypting and obfuscating log files.
- 🛡️ Stored as system and hidden files using file attribute manipulation.
