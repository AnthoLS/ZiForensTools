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