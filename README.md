# ZiForensTools

## Schedscan

Install :

```bash
wget https://raw.githubusercontent.com/AnthoLS/ZiForensTools/refs/heads/master/schedscan/schedscan.py -o schedscan.py
```

Then you just have to launch it to scan your tasks :

```powershell
python3 .\schedscan.py
```

You can use `-w` flag to specify a whitelist file. It have to be a `.txt` where each string is on one line and then another like the example in the repo.

## Dumper

### Python Method

Install :

```bash
git clone https://github.com/AnthoLS/ZiForensTools
```

Then go in the `dumper` folder and execute :

```bash
python3 .\procopener.py --pname "ureprocname"
```

### Exe method

> I advice you to use an external device when using this dumper in forensic context, to avoid risks of memory erase xhen execute th binary.
> 

Install :

```bash
wget https://github.com/AnthoLS/ZiForensTools/releases/download/Dumper/procopener.exe -o procopener.exe
```

Then you can execute as the same way than the python method :

```bash
.\procopener.exe --pname "ureprocname"
```

And then found `.map` &  `.raw` files with the PID number in your folder