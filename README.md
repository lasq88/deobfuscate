# deobfuscate
usage: deobfuscate.py [-h] [-m {replace,decompress,split,ascii}] file

Deobfuscates Emotet's powershell payload

positional arguments:
  file                  file with obfuscated code

optional arguments:
  -h, --help            show this help message and exit
  -m {replace,decompress,split,ascii}, --method {replace,decompress,split,ascii}
                        Specify obfuscation method

Written by Lasq / malfind.com
