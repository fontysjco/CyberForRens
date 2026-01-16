import sys
import hashlib
from dissect.target import Target
from datetime import datetime

def get_file_hash(target, path):
    """Haalt een SHA1 hash op van een specifiek bestand in het image."""
    try:
        # Dissect filesystem gebruiken om het bestand te openen
        with target.fs.open(path) as f:
            sha1 = hashlib.sha1()
            while chunk := f.read(8192):
                sha1.update(chunk)
            return sha1.hexdigest()
    except:
        return None

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport (Targeted) ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*45)

    try:
        target = Target.open(image_path)

        # [1] SYSTEEM INFORMATIE
        print("\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:    {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS/Versie:   {getattr(target, 'version', 'Onbekend')}")

        # [2] DETECTIE: VERDACHTE PADEN (Shimcache)
        print("\n[2] DETECTIE: VERDACHTE PADEN (Shimcache)")
        suspicious_files = []
        try:
            count = 0
            for entry in target.shimcache():
                path = str(entry.path)
                # We zoeken specifiek naar de Tor/VPN/Temp zaken die we eerder zagen
                if any(x in path.lower() for x in ["tor.exe", "protonvpn", "temp"]):
                    print(f"  [ALARM] Gevonden: {path}")
                    suspicious_files.append(path)
                    count += 1
                if count >= 10: break
            if not suspicious_files: print("  Geen direct verdachte paden gevonden in de top-resultaten.")
        except:
            print("  [-] Shimcache niet beschikbaar.")

        # [3] VERIFICATIE: TARGETED HASHING
        print("\n[3] VERIFICATIE: DIGITALE VINGERAFDRUKKEN (SHA1)")
        if suspicious_files:
            for path in list(set(suspicious_files)): # Unieke paden
                # We moeten het Windows-pad omzetten naar een Linux-stijl pad voor Dissect fs
                fs_path = path.replace("\\", "/").replace("C:", "")
                h = get_file_hash(target, fs_path)
                if h:
                    print(f"  - BESTAND: {path.split('\\')[-1]}")
                    print(f"    HASH:    {h}")
                else:
                    print(f"  - BESTAND: {path.split('\\')[-1]} (Kon hash niet berekenen)")
        else:
            print("  Geen bestanden gevonden voor verificatie.")

        print("\n" + "="*45 + "\nEinde Rapport")

    except Exception as e:
        print(f"\n[!] KRITIEKE FOUT: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        run_triage(sys.argv[1])
