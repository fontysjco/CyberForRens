import sys
from dissect.target import Target
from datetime import datetime

def analyze_target(t):
    """Functie om een specifiek (sub)target te analyseren"""
    hostname = getattr(t, 'hostname', 'Onbekend')
    print(f"\n[+] Analyse van Volume/Target: {hostname}")
    print(f"    OS: {t.os}")

    # [2] Persistence Check
    print(f"\n    [2] PERSISTENCE CHECK (Autoruns)")
    try:
        # Controleer of de plugin geladen is
        if hasattr(t.plugins, 'autoruns'):
            found = False
            for entry in t.plugins.autoruns.autoruns():
                path_str = str(entry.path).lower()
                if "temp" in path_str or path_str.endswith(".bat"):
                    print(f"      [VLAG] Verdacht: {entry.path}")
                    found = True
            if not found: print("      Geen verdachte autoruns gevonden.")
        else:
            print("      [-] Autoruns plugin niet beschikbaar voor dit volume.")
    except Exception as e:
        print(f"      [-] Fout bij autoruns: {e}")

    # [3] Execution History
    print(f"\n    [3] RECENTE EXECUTIE (Shimcache)")
    try:
        if hasattr(t.plugins, 'shimcache'):
            count = 0
            for entry in t.plugins.shimcache.shimcache():
                if count < 5:
                    print(f"      - {entry.path}")
                    count += 1
        else:
            print("      [-] Shimcache plugin niet beschikbaar op dit volume.")
    except Exception as e:
        print(f"      [-] Fout bij shimcache: {e}")

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    
    try:
        # Open het hoofd-image
        target = Target.open(image_path)
        
        # We maken een lijst van alle targets die we willen scannen
        to_scan = []

        # 1. Heeft het hoofdtarget zelf een OS?
        if target.os:
            to_scan.append(target)
        
        # 2. Heeft het subtargets (partities/volumes)?
        # We gebruiken een veilige check om de 'plugin' error te voorkomen
        subtargets = getattr(target, 'subtargets', [])
        for sub in subtargets:
            if sub.os:
                to_scan.append(sub)

        if not to_scan:
            print("[-] Geen partities met een besturingssysteem gevonden.")
            return

        for t in to_scan:
            analyze_target(t)

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Algemene fout bij analyse: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
