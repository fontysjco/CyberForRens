import sys
from dissect.target import Target
from datetime import datetime

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*40)

    try:
        # Stap 1: Open het image
        target = Target.open(image_path)

        # [1] SYSTEEM INFORMATIE
        print("\n[1] SYSTEEM & GEBRUIKERS")
        try:
            print(f"Hostname:    {getattr(target, 'hostname', 'Onbekend')}")
            print(f"OS/Versie:   {getattr(target, 'version', 'Onbekend')}")
            users = [u.name for u in target.user()]
            print(f"Gebruikers:  {', '.join(users)}")
        except Exception as e:
            print(f"  [-] Fout bij ophalen systeeminfo: {e}")

        # [2] RECENTE EXECUTIE (Shimcache)
        print("\n[2] RECENT UITGEVOERD (Shimcache)")
        try:
            count = 0
            # We roepen de functie aan met ()
            for entry in target.shimcache():
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
            if count == 0: print("  Geen data gevonden in Shimcache.")
        except Exception:
            print("  [-] Shimcache niet beschikbaar op dit image.")

        # [3] PERSISTENCE & SERVICES
        print("\n[3] PERSISTENCE & SERVICES")
        
        # Deel A: Autoruns
        try:
            print("  > Scannen op Autoruns...")
            count_auto = 0
            for entry in target.autoruns():
                path = str(entry.path).lower()
                if "temp" in path or "appdata" in path:
                    print(f"    [VLAG] Verdacht pad: {entry.path}")
                    count_auto += 1
            if count_auto == 0: print("    Geen verdachte autoruns gevonden.")
        except Exception:
            print("    [-] Autoruns plugin niet beschikbaar.")

        # Deel B: Services
        try:
            print("\n  > Scannen op Geïnstalleerde Services (Top 5)...")
            count_serv = 0
            for service in target.services():
                if count_serv < 5:
                    print(f"    - {service.name} ({service.display_name})")
                    count_serv += 1
            if count_serv == 0: print("    Geen services gevonden.")
        except Exception:
            print("    [-] Services plugin niet beschikbaar.")

        print("\n" + "="*40 + "\nEinde Rapport")

    except Exception as e:
        print(f"\n[!] KRITIEKE FOUT BIJ LADEN IMAGE: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        run_triage(sys.argv[1])
