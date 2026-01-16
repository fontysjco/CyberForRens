import sys
from dissect.target import Target
from datetime import datetime

def get_plugin_results(target, plugin_name):
    """Probeert op verschillende manieren de plugin data op te halen."""
    # Methode 1: Direct op het target (werkte voor shimcache!)
    plugin = getattr(target, plugin_name, None)
    if plugin and callable(plugin):
        try:
            return plugin()
        except:
            pass
            
    # Methode 2: Via de plugins manager
    try:
        if hasattr(target, 'plugins') and hasattr(target.plugins, plugin_name):
            plugin = getattr(target.plugins, plugin_name)
            return plugin()
    except:
        pass
        
    return None

def generate_report(image_path):
    print(f"--- Forensisch Triage Rapport ---")
    print(f"Datum: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Bron: {image_path}\n" + "="*30)
    
    try:
        target = Target.open(image_path)
        
        # [1] SYSTEEM INFORMATIE
        print(f"\n[1] SYSTEEM INFORMATIE")
        print(f"Hostname:  {getattr(target, 'hostname', 'Onbekend')}")
        print(f"OS:        {getattr(target, 'os', 'Onbekend')}")

        # [2] PERSISTENCE CHECK
        print(f"\n[2] PERSISTENCE CHECK (Autoruns)")
        # We proberen autoruns en als dat faalt, runkeys
        results = get_plugin_results(target, 'autoruns') or get_plugin_results(target, 'runkeys')
        if results:
            found = False
            for entry in results:
                path_str = str(entry.path).lower()
                if "temp" in path_str or "appdata" in path_str or path_str.endswith((".bat", ".ps1")):
                    print(f"  [VLAG] Verdacht: {entry.path}")
                    found = True
            if not found: print("  Geen direct verdachte persistence gevonden.")
        else:
            print("  [-] Geen persistence data beschikbaar.")

        # [3] RECENTE EXECUTIE (Shimcache)
        print(f"\n[3] RECENTE EXECUTIE (Shimcache)")
        results = get_plugin_results(target, 'shimcache')
        if results:
            count = 0
            for entry in results:
                if count < 10:
                    print(f"  - {entry.path}")
                    count += 1
            if count == 0: print("  Geen shimcache entries gevonden.")
        else:
            print("  [-] Shimcache data niet beschikbaar.")

        print(f"\n" + "="*30 + "\nEinde Rapport")

    except Exception as e:
        print(f"[-] Kritieke fout: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Gebruik: python3 triage.py <pad_naar_image>")
    else:
        generate_report(sys.argv[1])
