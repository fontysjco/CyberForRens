import sys
from dissect.target import Target
from datetime import datetime

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    
    try:
        # Open het image
        target = Target.open(image_path)
        
        # [1] SYSTEEM INFORMATIE
        print(f"\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:  {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS:        {getattr(target, 'os', 'Onbekend')}")
        print(f"Versie:    {getattr(target, 'version', 'Onbekend')}")

        # [2] PERSISTENCE CHECK (Autoruns)
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        try:
            # Check of de plugin in de plugin manager zit
            if "autoruns" in target.plugins:
                found = False
                # We roepen de plugin direct aan via de manager
                for entry in target.plugins.autoruns():
                    path_str = str(entry.path).lower()
                    # Zoek naar typische malware lokaties/extensies
                    if "temp" in path_str or "appdata" in path_str or path_str.endswith((".bat", ".ps1", ".vbs")):
                        print(f"  [VLAG] Verdacht: {entry.path}")
                        found = True
                if not found:
                    print("  Geen direct verdachte autoruns gevonden in de scan.")
            else:
                print("  [-] De 'autoruns' plugin kon niet worden geladen voor dit volume.")
        except Exception as e:
            print(f"  [-] Fout tijdens autoruns scan: {e}")

        # [3] RECENTE EXECUTIE (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            if "shimcache" in target.plugins:
                count = 0
                for entry in target.plugins.shimcache():
                    if count < 10: # We pakken de 10 meest recente
                        print(f"  - {entry.path}")
                        count += 1
                if count == 0:
                    print("  Geen shimcache entries gevonden.")
            else:
                print("  [-] De 'shimcache' plugin is niet beschikbaar voor dit image.")
        except Exception as e:
            print(f"  [-] Fout tijdens shimcache scan: {e}")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Kritieke fout bij openen image: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
