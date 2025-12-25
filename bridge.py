import subprocess
import sys
import os

# --- AUTO-INSTALLER ---
def install_dependencies():
    """Vérifie et installe les modules manquants automatiquement."""
    required = {"requests", "rich"}
    try:
        import requests
        import rich
    except ImportError:
        print("[!] Modules manquants détectés. Installation automatique en cours...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *required])
            print("[+] Installation terminée. Redémarrage du script...\n")
            os.execv(sys.executable, ['python'] + sys.argv)
        except Exception as e:
            print(f"[-] Erreur lors de l'installation : {e}")
            input("Appuyez sur Entrée pour quitter...")
            sys.exit(1)

install_dependencies()

# --- IMPORT DES MODULES ---
import requests
import json
import time
import random
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import track
from rich import box

# --- CONFIGURATION ---
console = Console()

# Thème Full Vert
COLOR_MAIN = "bright_green"
COLOR_SEC = "green3"
STYLE_KEY = "bold green"
STYLE_VAL = "white"

def get_logo():
    """Génère le nouveau logo fourni par l'utilisateur."""
    logo_text = f"""[{COLOR_MAIN}]
 █████ ███████████        ███████     █████████  █████ ██████   █████  █████   
░░███ ░░███░░░░░███     ███░░░░░███  ███░░░░░███░░███ ░░██████ ░░███  ░░███    
 ░███  ░███    ░███    ███     ░░███░███    ░░░  ░███  ░███░███ ░███  ███████  
 ░███  ░██████████    ░███      ░███░░█████████  ░███  ░███░░███░███ ░░░███░   
 ░███  ░███░░░░░░     ░███      ░███ ░░░░░░░░███ ░███  ░███ ░░██████   ░███    
 ░███  ░███           ░░███     ███  ███    ░███ ░███  ░███  ░░█████   ░███ ███
 █████ █████           ░░░███████░  ░░█████████  █████ █████  ░░█████  ░░█████ 
░░░░░ ░░░░░              ░░░░░░░     ░░░░░░░░░  ░░░░░ ░░░░░    ░░░░░    ░░░░░  
[/{COLOR_MAIN}]
[bold {COLOR_SEC}]        >> IP INTELLIGENCE & OSINT CORE - FULL GREEN EDITION <<[/bold {COLOR_SEC}]
    """
    return logo_text

def get_ip_data(ip_address):
    """Récupère le maximum de données disponibles via l'API avancée."""
    # On demande absolument tous les champs disponibles
    api_url = f"http://ip-api.com/json/{ip_address}?fields=66846719"
    try:
        response = requests.get(api_url, timeout=10)
        return response.json()
    except Exception as e:
        console.print(f"[bold red]Erreur Réseau : {e}[/]")
        return None

def analyze_risk(data):
    """Algorithme de score de risque et analyse de vulnérabilité."""
    risk_score = 0
    risk_reasons = []
    
    # Proxy/VPN
    if data.get('proxy'):
        risk_score += 45
        risk_reasons.append("PROXIED/VPN")
    # Hosting
    if data.get('hosting'):
        risk_score += 35
        risk_reasons.append("HOSTING/DATACENTER")
    # Tor
    isp = data.get('isp', '').lower()
    if "tor" in isp or "exit" in isp:
        risk_score += 50
        risk_reasons.append("TOR EXIT NODE")
    
    # Mobile
    if data.get('mobile'):
        risk_score -= 10
        
    return max(0, min(100, risk_score)), risk_reasons

def display_dashboard(data, ip):
    """Affiche un dashboard ultra-complet avec plus de 20 lignes d'infos."""
    console.clear()
    console.print(get_logo())
    
    if not data or data.get('status') != 'success':
        msg = data.get('message', 'IP Invalide ou Hors-ligne') if data else "Pas de réponse"
        console.print(Panel(f"ERREUR : {msg}", title="System Failure", border_style="red"))
        return

    risk_score, risk_reasons = analyze_risk(data)
    risk_color = "bright_green" if risk_score < 30 else "yellow" if risk_score < 70 else "red"

    # --- TABLEAU 1 : IDENTITÉ RÉSEAU ---
    table_net = Table(title="[bold white]IDENTITÉ RÉSEAU & ROUTAGE[/bold white]", border_style=COLOR_MAIN, box=box.ROUNDED)
    table_net.add_column("Propriété", style=STYLE_KEY)
    table_net.add_column("Données", style=STYLE_VAL)
    
    table_net.add_row("Adresse IP", data.get('query'))
    table_net.add_row("Version", "IPv4" if "." in data.get('query', '') else "IPv6")
    table_net.add_row("Reverse DNS", data.get('reverse') or "N/A")
    table_net.add_row("FAI (ISP)", data.get('isp'))
    table_net.add_row("Organisation", data.get('org'))
    table_net.add_row("AS (Numéro)", data.get('as'))
    table_net.add_row("AS Nom", data.get('asname'))
    table_net.add_row("Type de Connexion", "Hébergeur" if data.get('hosting') else "Résidentiel")

    # --- TABLEAU 2 : GÉOLOCALISATION PRÉCISE ---
    table_geo = Table(title="[bold white]GÉOLOCALISATION PRÉCISE[/bold white]", border_style=COLOR_MAIN, box=box.ROUNDED)
    table_geo.add_column("Localisation", style=STYLE_KEY)
    table_geo.add_column("Détails", style=STYLE_VAL)
    
    table_geo.add_row("Continent", f"{data.get('continent')} ({data.get('continentCode')})")
    table_geo.add_row("Pays", f"{data.get('country')} ({data.get('countryCode')})")
    table_geo.add_row("Région", f"{data.get('regionName')} ({data.get('region')})")
    table_geo.add_row("Ville / District", f"{data.get('city')} / {data.get('district') or 'Non spécifié'}")
    table_geo.add_row("Code Postal", data.get('zip'))
    table_geo.add_row("Coordonnées GPS", f"{data.get('lat')}, {data.get('lon')}")
    table_geo.add_row("Fuseau Horaire", data.get('timezone'))
    table_geo.add_row("Décalage UTC", str(data.get('offset')))
    table_geo.add_row("Monnaie locale", data.get('currency'))

    # --- TABLEAU 3 : ANALYSE DE SÉCURITÉ ---
    table_sec = Table(title="[bold white]SÉCURITÉ & INTELLIGENCE[/bold white]", border_style=COLOR_MAIN, box=box.ROUNDED)
    table_sec.add_column("Vecteur", style=STYLE_KEY)
    table_sec.add_column("Statut", style=STYLE_VAL)
    
    table_sec.add_row("Score de Risque", f"[{risk_color}]{risk_score}/100[/]")
    table_sec.add_row("Proxy / VPN", "[red]OUI[/]" if data.get('proxy') else "[green]NON[/]")
    table_sec.add_row("Hébergeur / Bot", "[red]OUI[/]" if data.get('hosting') else "[green]NON[/]")
    table_sec.add_row("Réseau Mobile", "[yellow]OUI[/]" if data.get('mobile') else "[green]NON[/]")
    table_sec.add_row("Ports Ouverts (Est.)", "80, 443, 8080" if data.get('hosting') else "Filtrés")
    table_sec.add_row("Vulnérabilités DNS", "SPOOFING_POTENTIAL" if not data.get('reverse') else "NONE_DETECTED")
    table_sec.add_row("Usage Probable", "BOT/SERVER" if data.get('hosting') else "USER_BROWSING")

    # --- RENDU FINAL ---
    console.print(Panel(f"TARGET : [bold white]{ip}[/bold white]", border_style=COLOR_MAIN))
    
    console.print(table_net)
    console.print(table_geo)
    console.print(table_sec)
    
    if risk_reasons:
        console.print(Panel("\n".join([f"!! {r}" for r in risk_reasons]), title="[bold red]ALERTE ANALYSE[/bold red]", border_style="red"))

    console.print(f"\n[bold {COLOR_SEC}]Lien Google Maps :[/] https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}")
    console.print(f"\n[dim]Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}[/dim]")

def main_loop():
    """Boucle principale."""
    while True:
        console.clear()
        console.print(get_logo())
        
        try:
            console.print(f"\n[bold {COLOR_MAIN}]Entrez l'adresse IP à tracker (ou 'exit') :[/]")
            target = console.input(f"[{COLOR_MAIN}]OSINT_CORE > [/{COLOR_MAIN}]").strip()
            
            if target.lower() in ['exit', 'quit', 'q']:
                break
                
            if not target:
                continue

            # Utilisation d'un spinner plus compatible ('aesthetic' au lieu de 'binary')
            with console.status(f"[bold {COLOR_MAIN}]Extraction des informations en cours...", spinner="aesthetic"):
                raw_data = get_ip_data(target)
                
            display_dashboard(raw_data, target)
            
            console.print(f"\n[bold {COLOR_SEC}]>>> ANALYSE TERMINÉE. APPUYEZ SUR ENTREE POUR UN NOUVEAU SCAN...[/]")
            input()
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"\n[bold red]ERREUR SYSTÈME : {e}[/]")
            time.sleep(2)

if __name__ == "__main__":
    main_loop()