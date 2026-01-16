import sys
import hashlib
from dissect.target import Target
from datetime import datetime

def get_file_hash(target, path):
    """Haalt een SHA1 hash op van een bestand door pad-inconsistenties te fixen."""
    # 1. Verwijder Windows-interne prefixes zoals \??\ en de schijfletter C:
    cleaned_path = path.replace("\\??\\", "").replace("C:", "").replace("c:", "")
    # 2. Zet alle backslashes om naar forward slashes voor de Dissect proxy
    cleaned_path = cleaned_path.replace("\\", "/")
    
    # 3. Zorg dat het pad altijd begint met een /
    if not cleaned_path.startswith("/"):
        cleaned_path = "/" + cleaned_path

    try:
        # We proberen het bestand te openen via het virtuele bestandssysteem van de target
        with target.fs.open(cleaned_path) as f:
            sha1 = hashlib.sha1()
            while chunk := f.read(8192):
                sha1.update(chunk)
            return sha1.hexdigest()
    except Exception:
        # Als het bestand niet gevonden wordt (bijv. al verwijderd), geven we None terug
        return None

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport (Final) ---")
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
            for entry in target.shimcache():
                path = str(entry.path)
                # Zoek specifiek naar indicatoren van Tor, VPN of Temp-executables
                if any(x in path.lower() for x in ["tor.exe", "protonvpn", "temp", "vc_redist"]):
                    if path not in suspicious_files:
                        print(f"  [ALARM] Gevonden: {path}")
                        suspicious_files.append(path)
                if len(suspicious_files) >= 15: break # Cap om rapport leesbaar te houden
        except:
            print("  [-] Shimcache niet beschikbaar.")

        # [3] VERIFICATIE: DIGITALE VINGERAFDRUKKEN (SHA1)
        print("\n[3] VERIFICATIE: DIGITALE VINGERAFDRUKKEN (SHA1)")
        if suspicious_files:
            for path in suspicious_files:
                filename = path.split('\\')[-1]
                h = get_file_hash(target, path)
                
                if h:
                    print(f"  - BESTAND: {filename}")
                    print(f"    HASH:    {h}")
                    print(f"    PAD:     {path}")
                else:
                    # Belangrijk forensisch inzicht: bestand staat in register maar is niet op schijf
                    print(f"  - BESTAND: {filename} (Niet meer op schijf aanwezig - mogelijk verwijderd)")
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
