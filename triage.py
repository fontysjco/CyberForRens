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

        # [2] PERSISTENCE CHECK (Autoruns & Runkeys)
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        try:
            found = False
            # We proberen de autoruns plugin via de plugin manager aan te roepen
            if hasattr(target.plugins, 'autoruns'):
                for entry in target.plugins.autoruns():
                    path_str = str(entry.path).lower()
                    if "temp" in path_str or "appdata" in path_str or path_str.endswith((".bat", ".ps1")):
                        print(f"  [VLAG] Verdacht: {entry.path}")
                        found = True
            
            # Als autoruns niets geeft, proberen we de specifiekere runkeys (Registry)
            if not found and hasattr(target.plugins, 'runkeys'):
                for entry in target.plugins.runkeys():
                    print(f"  - RunKey: {entry.path}")
                    found = True
                    
            if not found:
                print("  [-] Geen persistence data (autoruns/runkeys) gevonden op dit volume.")
        except Exception as e:
            print(f"  [-] Fout bij persistence scan: {e}")

        # [3] RECENTE EXECUTIE (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            # We weten dat deze werkt met de () aanroep!
            if hasattr(target.plugins, 'shimcache'):
                count = 0
                for entry in target.plugins.shimcache():
                    if count < 10:
                        print(f"  - {entry.path}")
                        count += 1
                if count == 0: print("  Geen shimcache entries gevonden.")
            else:
                print("  [-] Shimcache plugin niet beschikbaar.")
        except Exception as e:
            print(f"  [-] Fout bij shimcache scan: {e}")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Kritieke fout bij openen image: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
