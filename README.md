### AB2E - Angry Birds 2 Editor

This is an editor for the iOS and Android versions of Angry Birds 2

**BACK UP YOUR SAVES**

Save Locations:

iOS -> `/var/mobile/Containers/Data/Application/`

Android -> `/storage/emulated/0/Android/data/com.rovio.baba/files/save/`

This requires the files `B4F59D3E9582F13D98B85102B4003E377A9434837B71846F44C05637D2613FA1` and `index` from your device.

There is a file called `xor_key.bin` or the `-k/--key` argument that I'm not going to provide for legal reasons so you will have to find that yourself (it's easy to find, google it).

Usage is as follows:
```
usage: AB2E.py [-h] -i IN_FILE [-o OUT_FILE] [--index-file INDEX_FILE]
               [--gems GEMS] [--pearls PEARLS] [--spells SPELLS]
               [--tickets TICKETS] [--all-hats] [--max-cards]

A script for modding Angry Birds 2 saves

optional arguments:
  -h, --help            show this help message and exit
  -o OUT_FILE, --out-file OUT_FILE
                        The output file
  --index-file INDEX_FILE
                        The index file to use for encryption/decryption
  --gems GEMS           The amount of gems you want
  --pearls PEARLS       The amount of black pearls you want
  --spells SPELLS       The amount of spells you want
  --tickets TICKETS     The amount of arena tickets you want
  --all-hats            Give all hats
  --max-cards           Max all card levels

required arguments:
  -i IN_FILE, --in-file IN_FILE
                        The input file
```

**Disclaimer: I'm not responsible if you manage to get yourself banned using this!**