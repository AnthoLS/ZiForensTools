import psutil

def search_proc(target):
    # On liste les process exisants dans un dictionnaire
    # On leur associe le nom du process et l'utilisateur qui l'exécute
    procs = {p.pid: p.info for p in psutil.process_iter([ 'name', 'username'])}

    # On recherche le pid en fonction de la target donnée
    for pid, info in procs.items():
        if target in info['name']:
            return pid
        
    return False

if __name__ == "__main__" :
    print(search_proc("Notion"))