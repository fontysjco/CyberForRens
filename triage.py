import sys
from dissect.target import Target
from datetime import datetime

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    
    try:
        # We openen het image. Dissect vindt meestal zelf de juiste Windows-laag.
        target = Target.open(image_path)
        
        # [1] Systeem Informatie
        print(f"\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:  {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS:        {getattr(target, 'os', 'Onbekend')}")
        print(f"Versie:    {getattr(target, 'version', 'Onbekend')}")

        # [2] Persistence Check (Autoruns)
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        try:
            # We gebruiken de meest directe manier om plugins aan te roepen
            if hasattr(target, 'autoruns'):
                found = False
                for entry in target.autoruns():
                    path_str = str(entry.path).lower()
                    if "temp" in path_str or path_str.endswith(".bat"):
                        print(f"  [VLAG] Verdachte autorun: {entry.path}")
                        found = True
                if not found: print("  Geen verdachte autoruns gevonden.")
            else:
                print("  [-] Autoruns plugin niet geladen voor dit target.")
        except Exception as e:
            print(f"  [-] Fout bij uitvoeren autoruns: {e}")

        # [3] Execution History (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            if hasattr(target, 'shimcache'):
                count = 0
                for entry in target.shimcache():
                    if count < 10:
                        print(f"  - {entry.path}")
                        count += 1
            else:
                print("  [-] Shimcache plugin niet geladen.")
        except Exception as e:
            print(f"  [-] Fout bij uitvoeren shimcache: {e}")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Algemene fout bij laden van image: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
