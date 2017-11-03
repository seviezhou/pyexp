from lib.core.settings import UPPERLETTERS
from cipher.cryptomath import gcd
from cipher.cryptomath import findModInverse
from lib.core.expection import PyExpSystemException

def getKeyParts(key):
    keyA = key // len(UPPERLETTERS)
    keyB = key % len(UPPERLETTERS)
    return (keyA, keyB)

def checkKeys(keyA, keyB, mode):
    if keyA == 1 and mode == 'encrypt':
        msg = 'The affine cipher becomes incredibly weak when key A is set to 1. Choose a different key.'
        raise PyExpSystemException(msg)

    if keyB == 0 and mode == 'encrypt':
        msg = 'The affine cipher becomes incredibly weak when key B is set to 0. Choose a different key.'
        raise PyExpSystemException(msg)

    if keyA < 0 or keyB < 0 or keyB > len(UPPERLETTERS)-1:
        msg = 'Key A must be greater than 0 and Key B must be between 0 and %s.' % (len(UPPERLETTERS) - 1)
        raise PyExpSystemException(msg)

    if gcd(keyA, len(UPPERLETTERS)) != 1:
        msg = 'Key A (%s) and the symbol set size (%s) are not relatively prime. Choose a different key.' % (keyA, len(UPPERLETTERS))
        raise PyExpSystemException(msg)

def encryptMessage(key, message):
    keyA, keyB = getKeyParts(key)
    checkKeys(keyA, keyB, 'encrypt')
    ciphertext = ''
    for symbol in message.upper():
        if symbol in UPPERLETTERS:
            symIndex = UPPERLETTERS.find(symbol)
            ciphertext += UPPERLETTERS[(symIndex * keyA + keyB) % len(UPPERLETTERS)]
        else:
            ciphertext += symbol
    return ciphertext

def decryptMessage(key, message):
    keyA, keyB = getKeyParts(key)
    checkKeys(keyA, keyB, 'decrypt')
    plaintext = ''
    modInverseOfKeyA = findModInverse(keyA, len(UPPERLETTERS))

    for symbol in message.upper():
        if symbol in UPPERLETTERS:
            symIndex = UPPERLETTERS.find(symbol)
            plaintext += UPPERLETTERS[(symIndex - keyB) * modInverseOfKeyA % len(UPPERLETTERS)]
        else:
            plaintext += symbol
    return plaintext

def cipher(message, key, mode):

    key = int(key)

    if mode == 'encrypt':
        return encryptMessage(key, message)

    elif mode == 'decrypt':
        return decryptMessage(key, message)

def bruter(message):

    result = {}

    for key in range(len(UPPERLETTERS) ** 2):
        keyA = getKeyParts(key)[0]
        if gcd(keyA, len(UPPERLETTERS)) != 1:
            continue

        possibleResult = decryptMessage(key, message)
        result[key] = possibleResult

    return result
