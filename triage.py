import sys
from dissect.target import Target
from datetime import datetime

def analyze_target(t):
    """Functie om een specifiek (sub)target te analyseren"""
    print(f"\n[+] Analyse van Target: {t.hostname if hasattr(t, 'hostname') else 'Onbekend'}")
    print(f"    OS: {t.os}")

    # [2] Persistence Check
    print(f"\n    [2] PERSISTENCE CHECK (Autoruns)")
    try:
        # We proberen de plugin aan te roepen via de plugin manager
        found = False
        if hasattr(t.plugins, 'autoruns'):
            for entry in t.plugins.autoruns.autoruns():
                path_str = str(entry.path).lower()
                if "temp" in path_str or path_str.endswith(".bat"):
                    print(f"      [VLAG] Verdacht: {entry.path}")
                    found = True
            if not found: print("      Geen verdachte autoruns gevonden.")
        else:
            print("      [-] Autoruns plugin niet beschikbaar voor dit (sub)target.")
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
            print("      [-] Shimcache plugin niet beschikbaar.")
    except Exception as e:
        print(f"      [-] Fout bij shimcache: {e}")

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    
    try:
        # We openen het image 'recursief' om alle partities te vinden
        target = Target.open(image_path)
        
        # Soms is het hoofd-target leeg, maar zitten de data in 'subtargets' (partities)
        targets_to_scan = []
        if target.os: # Als het hoofdtarget een OS heeft
            targets_to_scan.append(target)
        
        # Voeg alle partities toe die een OS lijken te hebben
        for sub in target.subtargets:
            if sub.os:
                targets_to_scan.append(sub)

        if not targets_to_scan:
            print("[-] Geen besturingssysteem gevonden op de schijf/partities.")
            return

        for t in targets_to_scan:
            analyze_target(t)

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Algemene fout bij analyse: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
