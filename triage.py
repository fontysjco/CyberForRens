import sys
from dissect.target import Target
from datetime import datetime

def run_triage(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*40)

    try:
        target = Target.open(image_path)

        # [1] SYSTEEM INFORMATIE
        print("\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:    {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS/Versie:   {getattr(target, 'version', 'Onbekend')}")

        # [2] RECENTE EXECUTIE (Shimcache - DE BEWIJSLAST)
        print("\n[2] RECENT UITGEVOERD (Shimcache)")
        try:
            count = 0
            for entry in target.shimcache():
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
        except:
            print("  [-] Shimcache data niet beschikbaar.")

        # [3] APPLICATIE METADATA (Amcache - SHA1 Hashes)
        print("\n[3] APPLICATIE ANALYSE (Amcache)")
        try:
            print("  > Zoeken naar programma-hashes...")
            count_am = 0
            # Amcache geeft vaak de SHA1 hash van binaries
            for entry in target.amcache():
                if count_am < 10:
                    # We tonen de naam en de hash (indien aanwezig)
                    name = getattr(entry, 'name', 'Onbekend')
                    sha1 = getattr(entry, 'sha1', 'Geen hash')
                    print(f"  - {name} [SHA1: {sha1}]")
                    count_am += 1
            if count_am == 0:
                print("    Geen Amcache data gevonden.")
        except:
            print("    [-] Amcache plugin niet beschikbaar op dit systeem.")

        print("\n" + "="*40 + "\nEinde Rapport")

    except Exception as e:
        print(f"\n[!] KRITIEKE FOUT: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        run_triage(sys.argv[1])
