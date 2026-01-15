import sys
from dissect.target import Target
from datetime import datetime

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    try:
        target = Target.open(image_path)
        print(f"\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:  {target.hostname}")
        print(f"OS:        {target.os}")
        
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        for entry in target.tools.dumpit.autoruns():
            path_str = str(entry.path).lower()
            if "temp" in path_str or path_str.endswith(".bat"):
                print(f"  [VLAG] Verdachte autorun: {entry.path}")
                
        print(f"\n" + "="*30 + "\nEinde Rapport")
    except Exception as e:
        print(f"[-] Fout bij analyse: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
