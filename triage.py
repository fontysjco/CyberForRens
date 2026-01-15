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
        
        # [1] Systeem Informatie (Dit werkte al!)
        print(f"\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:  {target.hostname}")
        print(f"OS:        {target.os}")
        print(f"Versie:    {getattr(target, 'version', 'Onbekend')}")

        # [2] Persistence Check (Autoruns)
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        try:
            # We gebruiken de plugin manager direct
            for entry in target.plugins.autoruns.autoruns():
                path_str = str(entry.path).lower()
                if "temp" in path_str or path_str.endswith(".bat") or path_str.endswith(".ps1"):
                    print(f"  [VLAG] Verdacht: {entry.path}")
        except AttributeError:
            print("  [-] Autoruns plugin niet gevonden of niet ondersteund op dit image.")

        # [3] Execution History (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        try:
            count = 0
            for entry in target.plugins.shimcache.shimcache():
                if count < 5: # Top 5 resultaten om rapport kort te houden
                    print(f"  - {entry.path}")
                    count += 1
        except AttributeError:
            print("  [-] Shimcache plugin niet beschikbaar.")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Algemene fout bij analyse: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
