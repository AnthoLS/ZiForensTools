import ctypes
import ctypes.wintypes as wintypes
from pidsearch import search_proc 

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    PVOID = wintypes.LPVOID
    DWORD = wintypes.DWORD
    SIZE_T = ctypes.c_size_t

    _fields_ = [('BaseAddress', PVOID),
                ('AllocationBase', PVOID),
                ('AllocationProtect', DWORD),
                ("__alignment1", DWORD), # pour l'alignement 8-octets
                ('RegionSize', SIZE_T),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD),
                ("__alignment2", DWORD)]
                # En 64 bits, un PVOID fait 8 octets. AllocationProtect fait 4 octets. 
                # Sans le premier __alignment, Windows essaierait d'écrire RegionSize (8 octets) 
                # juste après, ce qui casserait l'alignement.

# Condiguration des signatures
k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t

k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL

k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE

# Explorer les régions mémoire
def explorer(process_handle: wintypes.HANDLE):
    MEM_COMMIT = 0x1000 # Paramètre qui nous permet de voir si la région est actuellement utilisée
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    
    memaddress = 0
    regions = []

    while True:
        mbi = MEMORY_BASIC_INFORMATION()
        exp = k32.VirtualQueryEx(process_handle,memaddress,ctypes.byref(mbi),ctypes.sizeof(mbi),)

        if exp == 0:
            error_code = k32.GetLastError()
            print(f"[-] VirtualQueryEx a échoué à l'adresse {hex(address)}. Code erreur : {error_code}")
            break
        
        print(f"[*] Analyse bloc : {hex(address)} | Taille : {mbi.RegionSize} | État : {hex(mbi.State)}")

        # On vient préviser les No ACCESS et GUARD pour éviter que le dump échoue sur les procees protégés
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_NOACCESS) and not (mbi.Protect & PAGE_GUARD):
                print(f"    [!] Région commit trouvée ! Tentative de lecture...")
                regions.append(
                    {
                        "base_address": mbi.BaseAddress,
                        "allocation_base": mbi.AllocationBase,
                        "size": mbi.RegionSize,
                        "type": mbi.Type,
                    }
                )
        memaddress += mbi.RegionSize

    return regions

# Lire les régions détectées comme occupées, et les retourner en bits
def reader(process_handle: wintypes.HANDLE, base_address: int, size: int):
    region_data = ctypes.create_string_buffer(size)

    if k32.ReadProcessMemory(process_handle, base_address, region_data, size, None):
        return region_data.raw
    else:
        return None

# Ouverture du process avec les bons droits
def open_process_handle(pid: int):
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    return k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

def get_memory_snapshot_by_window_title(window_title: str):
    pid = search_proc(window_title)
    if not pid:
        return []
    
    process_handle = open_process_handle(pid)
    if not process_handle:
        return []

    regions = explorer(process_handle)

    for i in range(len(regions)):
        data = reader(process_handle, regions[i]["base_address"], regions[i]["size"])
        regions[i]["data"] = data

    k32.CloseHandle(process_handle)

    return regions

def dumping(proc_name):
    pid = search_proc(proc_name)
    if not pid: return False
    
    handle = open_process_handle(pid)
    if not handle: return False

    rawfile = f"{pid}.raw"
    mapfile = f"{pid}.map"

    print(f"[*] Début du dump pour le PID {pid}...")

    with open(rawfile, "wb") as f_raw, open(mapfile, "w") as f_map:
        memaddress = 0
        
        while True:
            mbi = MEMORY_BASIC_INFORMATION()
            res = k32.VirtualQueryEx(handle, ctypes.c_void_p(memaddress), ctypes.byref(mbi), ctypes.sizeof(mbi))
            
            # Détection de fin de de la mémoire ou erreur
            if res == 0:
                break
            
            if mbi.State == 0x1000 and not (mbi.Protect & 0x01) and not (mbi.Protect & 0x100):
                data = reader(handle, mbi.BaseAddress, mbi.RegionSize)
                
                # Si on détecte un state intéressant, on insère son contenu dans le fichier
                if data:
                    current_offset = f_raw.tell()
                    
                    f_raw.write(data)
                    
                    f_map.write(f"VAddr: {hex(mbi.BaseAddress)} | Size: {mbi.RegionSize} | FileOffset: {current_offset}\n")
                    print(f"    [+] Dumpé: {hex(mbi.BaseAddress)} ({mbi.RegionSize} octets)")

            # On passe à la région suivante
            memaddress += mbi.RegionSize

    # Fermeture propre avec le handle obtenu plus tôt
    k32.CloseHandle(handle)
    print("[*] Dump terminé avec succès.")

if __name__ == "__main__":
    dumping("Notion")