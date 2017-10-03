#!/usr/bin/python3

#built-in imports
from os import urandom
from io import BytesIO
from os.path import isfile
from binascii import unhexlify
from struct import unpack, pack
from hashlib import sha1, sha256
from argparse import ArgumentParser
from json import loads, dumps as _dumps

#library imports
#pip install pycryptodomex
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

#Android Save Location
#/storage/emulated/0/Android/data/com.rovio.baba/files/save/
#iOS Save Location
#/var/mobile/Containers/Data/Application/(random GUID)/Documents/save/

#8DA4F614BD109FD64248704E48E720719DBA53061539CB4C46B6ECBA475C6E5C - Session_ID
#D8BEB2B529C8FAC1BC697121125618BF790BD7F87AE759266CA6CC9CC07B6035 - FriendsCache
#5CC8D4E0834E058B4A47D33C3B97BB1505D33A626B4C5A74699DE886B7BF871F - PVPPlayerData
#B2BD44808B01FEEE6C1B8917B851CEF64978B5560EA10368424F7EE9196DF6BA - BeaconAppConfig
#B4F59D3E9582F13D98B85102B4003E377A9434837B71846F44C05637D2613FA1 - CombinedPlayerData
#937A9CA7A99C29ADB867F6B0000DD6310FC7D9DEF559FC2436D0F0E64F0B3E3D - TowerOfFortuneState
#A664CA94E883A423A522AE9778BDB3B1379BD7FC72E90CCA361B1396E3BEC2E1 - LastTimeBundleWasRefreshed

#save locations
#ls -R /var/mobile/Containers/Data/Application/ | grep "Documents\/save"
DIR_ANDROID = "/storage/emulated/0/Android/data/com.rovio.baba/files/save/"

#files
FILE_PLAYER_DATA = "B4F59D3E9582F13D98B85102B4003E377A9434837B71846F44C05637D2613FA1"  #gen_key_hash("CombinedPlayerData")

#save keys
KEY_WALLET        = "PD_Wallet"
KEY_CARD_SPEC     = "PD_CardSpecCollection"
KEY_SPELLS        = "PD_NewSpellCollection"  #used to be PD_SpellCollection
KEY_PROGRESS      = "PD_PlayerProgress"
KEY_NOTIFICATIONS = "PD_GameNotifications"
KEY_FTUE          = "PD_FTUEData"
KEY_ARENA         = "PD_ArenaPlayerState"
KEY_COSTUMES      = "PD_CostumeData"
KEY_LOYALTY       = "PD_LoyaltyData"
KEY_OFFERS        = "PD_OfferData"
KEY_FEATS         = "PD_FeatsData"

#costumes
COSTUME_IDS = [
    "Party",
    "Mythic",
    "Wizard",
    "Christmas",
    "School",
    "Halloween",
    "Royal",
    "Street",
    "Beach",
    "Wigs",
    "Valentines",
    "Fruitshades",
    "Anniversary",
    "Cowboy",
    "Easter",
    "Work",
    "Sport",
    "Chef",
    "Pirate",
    "Knights",
    "Winter",
    "Pharaoh",
    "IceCream",
    "Fancy",
    "Steampunk"
]
#birds
BIRD_IDS = [
    "RedBird", "YellowBird", "BlueBird", "BlackBird", "PurpleBird", "WhiteBird", "TerenceBird"
]
#card specs
CARD_LEVEL_MAX = 49
CARD_LEVEL_MAX_TOKENS = 1194350

#key info
KEY_FILE = "xor_key.bin"
KEY_HASH = "ed2c60e414cfcb401ead9540bd0b716c2a898f38"

def dumps(o: object) -> str:
    """
    Format object to JSON string without whitespaces
    :param i: The input object
    :return: JSON string with whitespace removed
    """
    return _dumps(o, separators=(',', ':'))

class AB2_SAVE(object):
    data = None

    wallet = None
    cardspeccollection = None
    newspellcollection = None
    playerprogress = None
    gamenotifications = None
    ftuedata = None
    arenaplayerstate = None
    costumedata = None
    loyaltydata = None
    offerdata = None
    featsdata = None

    def __init__(self, json_data):
        self.data = loads(json_data)
        for (key, value) in [(x, globals()[x]) for x in globals().keys() if "KEY_" in x]:
            if getattr(self, value, None) is None:
                if value in self.data:
                    #print("setting variable %s = %s" % (value.lower(), loads(self.data[value])))
                    new_value = loads(self.data[value])
                    self.data[value] = new_value
                    setattr(self, value.lower().replace("pd_", ""), new_value)

    def get_json(self) -> str:
        out_data = self.data
        if self.wallet is not None:
            out_data[KEY_WALLET] = dumps(self.wallet)
        if self.cardspeccollection is not None:
            out_data[KEY_CARD_SPEC] = dumps(self.cardspeccollection)
        if self.newspellcollection is not None:
            out_data[KEY_SPELLS] = dumps(self.newspellcollection)
        if self.playerprogress is not None:
            out_data[KEY_PROGRESS] = dumps(self.playerprogress)
        if self.gamenotifications is not None:
            out_data[KEY_NOTIFICATIONS] = dumps(self.gamenotifications)
        if self.ftuedata is not None:
            out_data[KEY_FTUE] = dumps(self.ftuedata)
        if self.arenaplayerstate is not None:
            out_data[KEY_ARENA] = dumps(self.arenaplayerstate)
        if self.costumedata is not None:
            out_data[KEY_COSTUMES] = dumps(self.costumedata)
        if self.loyaltydata is not None:
            out_data[KEY_LOYALTY] = dumps(self.loyaltydata)
        if self.offerdata is not None:
            out_data[KEY_OFFERS] = dumps(self.offerdata)
        if self.featsdata is not None:
            out_data[KEY_FEATS] = dumps(self.featsdata)
        return dumps(out_data)

    def __str__(self) -> str:
        return self.get_json()

def is_json(data: str) -> bool:
    """
    Checks to see if a string is valid JSON
    :param data: the JSON string to check
    :return: whether the string is valid JSON or not
    """
    try:
        loads(data)
        return True
    except:
        return False

def load_index(path: str = "index") -> (AES, None):
    """
    Loads an index file from a given path
    :param path: the path to the index file
    :return: AES instance on success and none on failure
    """
    assert isfile(path), "\"%s\" not found!" % (path)
    buff = bytearray(open(path, "rb").read())
    for i in range(4, len(buff)):
        buff[i] ^= l_433[(i - 4) % len(l_433)]
    br = BytesIO(buff)
    numArr1 = br.read(2)
    num = unpack("<h", br.read(2))[0]
    if numArr1[0] == 171 and numArr1[1] == 186 and num == 1:
        c1 = unpack("<h", br.read(2))[0]
        c2 = unpack("<h", br.read(2))[0]
        if c1 + c2 + 4 + 4 == len(buff):
            numArr2 = br.read(c1)  #AES IV
            numArr3 = br.read(c2)  #AES key
            return AES.new(numArr3, AES.MODE_CBC, iv=numArr2)

def gen_index() -> (tuple, list):
    """
    Generates a fresh index file if you're lazy
    :return: a tuple/list of the AES key, AES IV, and raw index data
    """
    aes_key = urandom(32)
    aes_iv = urandom(16)
    bio = BytesIO()
    bio.write(bytearray([171, 186]))
    bio.write(pack("<hhh", 1, len(aes_iv), len(aes_key)) + aes_iv + aes_key)
    arr = bytearray(bio.getvalue())
    for i in range(4, len(arr)):
        arr[i] ^= l_433[(i - 4) % len(l_433)]
    return (aes_key, aes_iv, bytes(arr))

def gen_index_file(out_file: str = "index") -> None:
    """
    Generate an index file for encrypting saves
    :param out_file: the name of the file to save to
    :return: none
    """
    (aes_key, aes_iv, index_data) = gen_index()
    open(out_file, "wb").write(index_data)

def decrypt_save(data: (bytes, bytearray), index_path: str = "index") -> str:
    """
    Decrypts the Angry Birds 2 save file
    :param data: the save data as a bytearray or bytes object
    :return: decrypted JSON data
    """
    aes = load_index(index_path)
    assert aes is not None, "Invalid index file!"
    dec_data = str(unpad(aes.decrypt(data), AES.block_size), "utf8").replace("\x00", "")
    assert is_json(dec_data), "Save data decryption failed"
    return dec_data

def encrypt_save(data: str, index_path: str = "index") -> (bytes, bytearray):
    """
    Encrypts a JSON string to an Angry Birds 2 save file
    :param data: the JSON data to be encrypted
    :return: encrypted save data
    """
    assert is_json(data), "Invalid JSON data!"
    aes = load_index(index_path)
    assert aes is not None, "Invalid index file!"
    b = b""
    for x in range(0, len(data)):
        b += bytes(data[x], "utf8") + b"\x00"
    return aes.encrypt(bytes(pad(b, AES.block_size)))

def decrypt_save_file(in_file: str, out_file: str = None, index_path: str = "index") -> (str, None):
    """
    Decrypt a save file directly
    :param in_file: the input save file
    :param out_file: the output JSON file
    :return: string if out_file not specified, otherwise it's written to a file
    """
    assert isfile(in_file), "Input file missing!"
    dec_save_game = decrypt_save(open(in_file, "rb").read(), index_path)
    if out_file is None:
        return dec_save_game
    else:
        open(out_file, "w").write(dec_save_game)

def encrypt_save_file(in_file: str, out_file: str = None, index_path: str = "index") -> (bytes, bytearray, None):
    """
    Encrypt a JSON file directly
    :param in_file: the input JSON file
    :param out_file: the output save file
    :return: bytes/bytearray if out_file not specified, otherwise it's written to a file
    """
    assert isfile(in_file), "Input file missing!"
    save_json = open(in_file, "r").read()
    assert is_json(save_json), "Invalid JSON data!"
    enc_save_game = encrypt_save(save_json, index_path)
    if out_file is None:
        return enc_save_game
    else:
        open(out_file, "wb").write(enc_save_game)

def gen_key_hash(key: str) -> str:
    """
    Converts the key into a hash for different save files
    :param key: the key to hash
    :return: the hash of the key
    """
    b = b""
    for x in range(0, len(key)):
        b += bytes(key[x], "utf8") + b"\x00"
    return sha256(l_433 + b).hexdigest().upper()

def run_tests(path: str) -> None:
    """
    Runs tests on a given save file
    :param path: the path to the save file
    :return: none
    """
    assert isfile(path), "%s not found!" % (path)
    print("Running tests...")
    print("Decrypt #1")
    dec_save_0 = decrypt_save(open(path, "rb").read())
    print("Encrypt #1")
    enc_save_0 = encrypt_save(dec_save_0)
    print("Decrypt #2")
    dec_save_1 = decrypt_save(enc_save_0)
    print("Encrypt #2")
    enc_save_1 = encrypt_save(dec_save_1)
    print("Decryption round #1")
    print("Successful" if dec_save_0 == dec_save_1 else "Unsuccessful")
    print("Encryption round #2")
    print("Successful" if enc_save_0 == enc_save_1 else "Unsuccessful")

if __name__ == "__main__":
    parser = ArgumentParser(description="A script for modding Angry Birds 2 saves")
    #commands
    group_required = parser.add_argument_group("required arguments")
    group_required.add_argument("-i", "--in-file", type=str, required=True, help="The input file")
    parser.add_argument("-o", "--out-file", type=str, default="modded.sav", help="The output file")
    parser.add_argument("--index-file", type=str, default="index", help="The index file to use for encryption/decryption")
    parser.add_argument("--key", type=str, help="The xor key in hex aka l_433")

    #ints
    parser.add_argument("--gems", type=int, help="The amount of gems you want")
    parser.add_argument("--pearls", type=int, help="The amount of black pearls you want")
    parser.add_argument("--spells", type=int, help="The amount of spells you want")
    parser.add_argument("--tickets", type=int, help="The amount of arena tickets you want")
    #bools
    parser.add_argument("--all-hats", action="store_true", help="Give all hats")
    parser.add_argument("--max-cards", action="store_true", help="Max all card levels")
    args = parser.parse_args()

    assert isfile(args.in_file), "Input file not found!"
    assert isfile(args.index_file), "\"index\" file not found!"


    if args.key is not None:
        l_433 = unhexlify(args.key)
    elif isfile(KEY_FILE):
        l_433 = open(KEY_FILE, "rb").read()
    else:
        raise Exception("The XOR key xor_key.bin or as --key command line parameter was not specified")
    assert len(l_433) == 0x100 and sha1(l_433).hexdigest() == KEY_HASH, "Key file is invalid!"

    #load the save
    save = AB2_SAVE(decrypt_save_file(args.in_file, index_path=args.index_file))
    #set gems
    if args.gems and args.gems > 0:
        save.wallet["Gems"] = args.gems
    #set pearls
    if args.pearls and args.pearls > 0:
        save.wallet["SecondaryCurrency"] = args.pearls
    #set spells
    if args.spells and args.spells > 0:
        for x in range(0, len(save.newspellcollection["Spells"])):
            tmp = save.newspellcollection["Spells"][x]
            tmp["Count"] = args.spells
            save.newspellcollection["Spells"][x] = tmp
    #set arena tickets
    if args.tickets and args.tickets > 0:
        save.arenaplayerstate["ConsumableTicketCount"] = 9999
        save.arenaplayerstate["HasTicket"] = True
    #give all costumes
    if args.all_hats:
        all_costumes = []
        for bird in BIRD_IDS:
            for costume in COSTUME_IDS:
                all_costumes.append({"BirdId": bird, "SetId": costume})
        save.costumedata["OwnedParts"] = all_costumes
    #max card levels
    if args.max_cards:
        for x in range(0, len(save.cardspeccollection["CardSpecifications"])):
            tmp = save.cardspeccollection["CardSpecifications"][x]
            tmp["Level"] = CARD_LEVEL_MAX
            tmp["Tokens"] = CARD_LEVEL_MAX_TOKENS
            save.cardspeccollection["CardSpecifications"][x] = tmp

    #write the save to a file
    open(args.out_file, "wb").write(encrypt_save(save.get_json(), args.index_file))