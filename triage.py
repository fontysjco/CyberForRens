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

        # [3] PERSISTENCE (Registry RunKeys - De kern van malware startup)
        print("\n[3] PERSISTENCE (Registry RunKeys)")
        try:
            found = False
            for entry in target.runkeys():
                print(f"  - {entry.key}: {entry.value}")
                found = True
            if not found: print("  Geen RunKeys gevonden.")
        except:
            print("  [-] RunKeys niet beschikbaar.")

        print("\n" + "="*40 + "\nEinde Rapport")

    except Exception as e:
        print(f"\n[!] KRITIEKE FOUT: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        run_triage(sys.argv[1])
