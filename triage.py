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
            # We halen de plugin op. Let op de haakjes () bij de aanroep!
            autoruns_func = getattr(target, 'autoruns', None)
            if autoruns_func:
                found = False
                for entry in autoruns_func(): # AANROEPEN ALS FUNCTIE
                    path_str = str(entry.path).lower()
                    if "temp" in path_str or "appdata" in path_str or path_str.endswith((".bat", ".ps1")):
                        print(f"  [VLAG] Verdacht: {entry.path}")
                        found = True
                if not found: print("  Geen direct verdachte autoruns gevonden.")
            else:
                print("  [-] Autoruns plugin niet gevonden op dit systeem.")
        except Exception as e:
            print(f"  [-] Fout bij uitvoeren autoruns: {e}")

        # [3] RECENTE EXECUTIE (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            shim_func = getattr(target, 'shimcache', None)
            if shim_func:
                count = 0
                for entry in shim_func(): # AANROEPEN ALS FUNCTIE
                    if count < 10:
                        print(f"  - {entry.path}")
                        count += 1
                if count == 0: print("  Geen shimcache entries gevonden.")
            else:
                print("  [-] Shimcache plugin niet gevonden.")
        except Exception as e:
            print(f"  [-] Fout bij uitvoeren shimcache: {e}")

        # [4] GEINSTALLEERDE PROGRAMMA'S (De "win" van de vorige keer!)
        print(f"\n[4] GEINSTALLEERDE PROGRAMMA'S")
        try:
            prog_func = getattr(target, 'programs', None)
            if prog_func:
                count = 0
                for prog in prog_func(): # AANROEPEN ALS FUNCTIE
                    if count < 10:
                        print(f"  - {prog.name} ({prog.version})")
                        count += 1
            else:
                print("  [-] Programs plugin niet gevonden.")
        except Exception as e:
            print(f"  [-] Fout bij ophalen programma's: {e}")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Kritieke fout bij openen image: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
