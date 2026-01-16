import sys
from dissect.target import Target
from datetime import datetime

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*40)

    try:
        target = Target.open(image_path)

        # [1] SYSTEEM & GEBRUIKERS
        print("\n[1] SYSTEEM & GEBRUIKERS")
        print(f"Hostname:    {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS/Versie:   {getattr(target, 'version', 'Onbekend')}")
        try:
            # Gebruikers ophalen via de plugin manager (meest robuust)
            user_list = []
            if hasattr(target.plugins, 'user'):
                user_list = [u.name for u in target.plugins.user()]
            elif hasattr(target, 'user'):
                user_list = [u.name for u in target.user()]
            
            print(f"Gebruikers:  {', '.join(user_list) if user_list else 'Geen gevonden'}")
        except:
            print("Gebruikers:  Informatie niet beschikbaar.")

        # [2] RECENT UITGEVOERD (Shimcache - DEZE WERKT!)
        print("\n[2] RECENT UITGEVOERD (Shimcache)")
        try:
            count = 0
            for entry in target.shimcache():
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
        except:
            print("  [-] Shimcache niet beschikbaar.")

        # [3] PERSISTENCE & SERVICES
        print("\n[3] PERSISTENCE & SERVICES")
        
        # Autoruns via de officiële plugin-manager
        try:
            print("  > Scannen op Autoruns...")
            if hasattr(target.plugins, 'autoruns'):
                count_auto = 0
                for entry in target.plugins.autoruns():
                    path = str(entry.path).lower()
                    if "temp" in path or "appdata" in path:
                        print(f"    [VLAG] Verdacht: {entry.path}")
                        count_auto += 1
                if count_auto == 0: print("    Geen verdachte autoruns gevonden.")
            else:
                print("    [-] Autoruns plugin niet geladen in Target.")
        except:
            print("    [-] Fout tijdens autoruns scan.")

        # Services via de officiële plugin-manager
        try:
            print("\n  > Scannen op Geïnstalleerde Services (Top 5)...")
            if hasattr(target.plugins, 'services'):
                count_serv = 0
                for service in target.plugins.services():
                    if count_serv < 5:
                        print(f"    - {service.name} ({service.display_name})")
                        count_serv += 1
            else:
                print("    [-] Services plugin niet geladen in Target.")
        except:
            print("    [-] Fout tijdens services scan.")

        print("\n" + "="*40 + "\nEinde Rapport")

    except Exception as e:
        print(f"\n[!] KRITIEKE FOUT: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        run_triage(sys.argv[1])
