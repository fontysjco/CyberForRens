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
            found = False
            # We roepen de plugin direct aan via de namespace
            # Dissect plugins zijn vaak direct beschikbaar onder target.plugins.<naam>
            for entry in target.plugins.autoruns:
                path_str = str(entry.path).lower()
                if "temp" in path_str or "appdata" in path_str or path_str.endswith((".bat", ".ps1")):
                    print(f"  [VLAG] Verdacht: {entry.path}")
                    found = True
            if not found:
                print("  Geen direct verdachte autoruns gevonden.")
        except Exception:
            print("  [-] Autoruns plugin niet beschikbaar of geen data gevonden op dit volume.")

        # [3] RECENTE EXECUTIE (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            count = 0
            # Shimcache is een standaard plugin in de Windows-namespace van Dissect
            for entry in target.plugins.shimcache:
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
            if count == 0:
                print("  Geen shimcache entries gevonden.")
        except Exception:
            print("  [-] Shimcache plugin niet beschikbaar op dit image.")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Kritieke fout: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
