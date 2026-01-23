import os
import argparse
import xml.etree.ElementTree as ET

# Dossier contenant les taches planifiées
TASKS_DIR = "C:\Windows\System32\Tasks"
NAMESPACE = {"task": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

parser = argparse.ArgumentParser(description='Scan your scheduled tasks')
parser.add_argument('-w', type=str, dest='whitelist_path', required=False, help='Path of your whitelist')
args = parser.parse_args()

def search_tasks():
    # Initialisation d'une liste pour les répertorier
    tasks = []

    # On va chercher les fichiers un à un
    for root, dirs, files in os.walk(TASKS_DIR):
        for file in files:
            # On les liste
            full_path = os.path.join(root, file)
            tasks.append(full_path)
    return tasks 

# On cherche si la tâche est cachée ou non
def hidden_detection(root):
    hidden_elem = root.find(".//task:Hidden", NAMESPACE)
    if hidden_elem is not None and hidden_elem.text == "true":
        return True
    return False

# On voit si la tâche tente de s'exécuter au plus haut level
def runlevel_detection(root):
    runlevel = root.find(".//task:RunLevel", NAMESPACE)
    if runlevel is not None and runlevel.text == "HighestAvailable":
        return True
    return False

# On vérifie si la tache effectue un nombre suspect de commandes
def multiple_commands_detection(root):
    commands = root.findall(".//task:Command", NAMESPACE)
    
    if len(commands) > 3:
        return True
    return False

# On vérifie si il n'y a pas de commande encodée
def suspicious_args_detection(root):
    args_elem = root.find(".//task:Arguments", NAMESPACE)
    if args_elem is not None:
        args_text = args_elem.text.lower()
        # Détecte le base64 powershell ou le mode caché
        if "-enc" in args_text or "-windowstyle hidden" in args_text:
            return True
    return False

# On vérifie si la tache agit sur des dossiers suspects
def suspicious_path_detection(root):
    suspicious_dirs = ["temp", "public", "appdata", "programdata"]
    commands = root.findall(".//task:Command", NAMESPACE)
    for cmd in commands:
        if cmd.text and any(dir in cmd.text.lower() for dir in suspicious_dirs):
            return True
    return False

# Chargement de la whitelist
def load_whitelist(path):
    whitelist = []
    if path and os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                # On nettoie chaque ligne et on ignore les vides
                whitelist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Erreur lors du chargement de la whitelist: {e}")
    return whitelist

# Ajout de la fonction de whitelisting sur les détections
def is_whitelisted(task_name, task_author, whitelist):
    full_whitelist = whitelist + ["Microsoft"]
    
    for item in full_whitelist:
        if item.lower() in task_name.lower() or item.lower() in task_author.lower():
            return True
    return False

# Analyse des tasks répertoriées
def analyze_tasks(files, whitelist):
    suspicious = []
    for file_path in files:
        try:
            # On set le score et on parse le fichier
            score = 0
            tree = ET.parse(file_path)
            root = tree.getroot()
            # On récupère le nom du fichier pour ensuite réferrer son score
            task_name = os.path.relpath(file_path, TASKS_DIR)
            # Récupération de l'auteur
            author_elem = root.find(".//task:Author", NAMESPACE)
            task_author = author_elem.text if author_elem is not None else "Inconnu"
            # Analyse en fonction de chaque paramètre suspect
            if hidden_detection(root):
                score = score + 2
            if runlevel_detection(root):
                score = score + 1
            if multiple_commands_detection(root):
                score = score + 1
            if suspicious_args_detection(root):
                score = score + 3
            if suspicious_path_detection(root):
                score = score + 1
            # On filtre sur les tâches avec le score le plus élevé, en enlevant les tâches légitimes de Microsoft
            if score >= 3:
                if not is_whitelisted(task_name, task_author, whitelist):
                    suspicious.append({
                        "name": task_name,
                        "author": task_author,
                        "path": file_path,
                        "score": score
                    })
        except Exception:
            continue

    # Affichage propre des résultats
    if not suspicious:
        print("Aucune tâche suspecte détectée.")
    else:
        print(f"{'SCORE':<7} | {'AUTEUR':<20} | {'NOM DE LA TACHE'}")
        print("-" * 60)
    for task in sorted(suspicious, key=lambda x: x['score'], reverse=True):            
        print(f"{task['score']:<7} | {task['author']:<20} | {task['name']}")
    
    return suspicious

# Exécution
if __name__ == "__main__":
    # Chargement de la whitelist
    loaded_whitelist = load_whitelist(args.whitelist_path)
    if loaded_whitelist:
        print(f"[*] Whitelist chargée ({len(loaded_whitelist)} éléments).")
    
    taches = search_tasks()
    analyze_tasks(taches, loaded_whitelist)
    