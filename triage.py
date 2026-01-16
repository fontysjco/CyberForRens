import sys
from dissect.target import Target
from datetime import datetime

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport (Basis) ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*40)

    try:
        # Image openen
        target = Target.open(image_path)

        # [1] SYSTEEM & GEBRUIKERS (Attributie)
        print("\n[1] SYSTEEM & GEBRUIKERS")
        print(f"Hostname:    {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS/Versie:   {getattr(target, 'version', 'Onbekend')}")
        try:
            users = [u.name for u in target.user()]
            print(f"Gebruikers:  {', '.join(users)}")
        except:
            print("Gebruikers:  Kon gebruikerslijst niet ophalen.")

        # [2] RECENTE EXECUTIE (Shimcache - Zeer betrouwbaar in Dissect)
        print("\n[2] RECENT UITGEVOERD (Shimcache)")
        try:
            # We proberen de meest directe weg
            count = 0
            for entry in target.shimcache(): 
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
            if count == 0: print("  Geen data gevonden.")
        except:
            print("  [-] Shimcache niet beschikbaar.")

       # [3] PERSISTENCE (Autoruns & Services)
        print("\n[3] PERSISTENCE & SERVICES")
        
        # Probeer eerst de brede autoruns scan
        try:
            print("  > Scannen op Autoruns...")
            count_auto = 0
            for entry in target.autoruns():
                # We filteren op veelvoorkomende malware locaties om ruis te voorkomen
                path = str(entry.path).lower()
                if "temp" in path or "appdata" in path:
                    print(f"    [VLAG] Verdacht pad: {entry.path}")
                    count_auto += 1
            if count_auto == 0: print("    Geen verdachte autoruns gevonden.")
        except:
            print("    [-] Autoruns plugin niet beschikbaar.")

        # Probeer daarna Services (vaak stabieler in Dissect)
        try:
            print("\n  > Scannen op Geïnstalleerde Services (Top 5)...")
            count_serv = 0
            for service in target.services():
                if count_serv < 5:
                    print(f"    - {service.name} ({service.display_name})")
                    count_serv += 1
            if count_serv == 0: print("    Geen services gevonden.")
        except:
            print("    [-] Services plugin niet beschikbaar.")
