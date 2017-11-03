from lib.core.settings import LETTERS
from lib.core.settings import UPPERLETTERS
from lib.core.settings import LOWERLETTERS

def cipher(message, key, mode):

    key = int(key)

    if mode == 'encrypt':
        translated = ''
        for symbol in message:
            if symbol in LETTERS:
                if (ord(symbol) >= 97) & (ord(symbol) <= 122):
                    translated += LOWERLETTERS[(ord(symbol) - ord('a') + key) % 26]
                elif (ord(symbol) >= 65) & (ord(symbol) <= 90):
                    translated += UPPERLETTERS[(ord(symbol) - ord('A') + key) % 26]
            else:
                translated += symbol
        return translated

    elif mode == 'decrypt':
        translated = ''
        for symbol in message:
            if symbol in LETTERS:
                if (ord(symbol) >= 97) & (ord(symbol) <= 122):
                    translated += LOWERLETTERS[(ord(symbol) - ord('a') - key) % 26]
                elif (ord(symbol) >= 65) & (ord(symbol) <= 90):
                    translated += UPPERLETTERS[(ord(symbol) - ord('A') - key) % 26]
            else:
                translated += symbol
        return translated
    else:
        return None

def bruter(message):

    result = {}

    for key in range(26):
        translated = ''
        for symbol in message:
            if symbol in LETTERS:
                if (ord(symbol) >= 97) & (ord(symbol) <= 122):
                    translated += LOWERLETTERS[(ord(symbol) - ord('a') - key) % 26]
                elif (ord(symbol) >= 65) & (ord(symbol) <= 90):
                    translated += UPPERLETTERS[(ord(symbol) - ord('A') - key) % 26]
            else:
                translated += symbol
        result[key] = translated

    return result