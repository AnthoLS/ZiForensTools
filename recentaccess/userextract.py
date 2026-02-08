#!/usr/bin/env python3
import json
import os
import struct
import winreg
from pathlib import Path
from datetime import datetime, timedelta

OUTPUT_FILE = "data/artefacts_raw.json"
events = []

# Récupérer le répertoire utilisateur courant
user = os.getenv('USERNAME')
appdata = os.getenv('APPDATA')
recent_path = os.path.join(appdata, r"Microsoft\Windows\Recent")
ntuser_path = os.path.expanduser(r"~\NTUSER.DAT")

# ---- Fichiers LNK ----
def parse_lnk_basic(lnk_path):
    """Parse basique d'un fichier .lnk pour extraire des informations"""
    try:
        with open(lnk_path, "rb") as f:
            data = f.read()
        
        # Vérifier la signature LNK
        if len(data) < 76 or data[:4] != b'\x4c\x00\x00\x00':
            return None
        
        # Extraire le timestamp (offset 32, 8 bytes, little-endian, 100-nanosecond intervals since 1601)
        try:
            timestamp_raw = struct.unpack('<Q', data[32:40])[0]
            # Convertir depuis FILETIME Windows
            if timestamp_raw > 0:
                # 116444736000000000 = nombre de 100-nanos entre 1601 et 1970
                timestamp = datetime.fromtimestamp((timestamp_raw - 116444736000000000) / 10000000)
            else:
                timestamp = None
        except:
            timestamp = None
        
        # Essayer d'extraire le chemin (complexe, voir la chaîne Unicode après les headers)
        target_path = None
        try:
            # Chercher des chemins potentiels dans les données
            text_data = data.decode('utf-16-le', errors='ignore')
            # Chercher des caractères typiques du chemin
            parts = [line for line in text_data.split('\x00') if '\\' in line or '.exe' in line.lower()]
            if parts:
                target_path = parts[0][:260]  # Limiter à MAX_PATH
        except:
            pass
        
        return {
            "timestamp": timestamp.isoformat() if timestamp else None,
            "path": target_path if target_path else lnk_path.name
        }
    except Exception as e:
        return None

print(f"[+] Traitement des fichiers .lnk depuis: {recent_path}")
if os.path.exists(recent_path):
    for lnk_path in Path(recent_path).glob("*.lnk"):
        lnk_data = parse_lnk_basic(str(lnk_path))
        if lnk_data:
            events.append({
                "source": "LNK",
                "timestamp": lnk_data["timestamp"],
                "action": "FILE_OPEN",
                "path": lnk_data["path"],
                "user": user,
                "file": lnk_path.name
            })
else:
    print(f"[-] Le dossier Recent n'existe pas: {recent_path}")

# ---- RecentDocs Registry ----
print(f"[+] Lecture du registre RecentDocs")
try:
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
        num_values = winreg.QueryInfoKey(key)[1]
        for i in range(num_values):
            value_name, value_data, value_type = winreg.EnumValue(key, i)
            
            if value_name != "MRUList":
                # Convertir bytes si nécessaire
                if isinstance(value_data, bytes):
                    try:
                        value_data = value_data.decode('utf-8', errors='ignore')
                    except:
                        value_data = value_data.hex()
                
                events.append({
                    "source": "RECENTDOCS",
                    "timestamp": datetime.now().isoformat(),
                    "action": "RECENT_FILE",
                    "path": str(value_data),
                    "user": user,
                    "registry_value": value_name
                })
except Exception as e:
    print(f"[-] Erreur lecture registre: {e}")

# Créer le répertoire si nécessaire
Path("data").mkdir(exist_ok=True)

# Sauvegarder
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

print(f"[+] Artefacts extraits: {len(events)} enregistrements")
print(f"[+] Sauvegardés dans: {OUTPUT_FILE}")
