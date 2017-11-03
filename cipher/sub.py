from lib.core.settings import UPPERLETTERS
from lib.core.settings import nonLettersOrSpacePattern
from lib.core.expection import PyExpSyntaxException
from lib.techniques.makeWordPatterns import getFullPatterns
from lib.techniques.makeWordPatterns import getWordPattern
from lib.core.data import logger
from lib.core.common import dataToStdout

import pprint
import copy

def checkValidKey(key):
    keyList = list(key.upper())
    lettersList = list(UPPERLETTERS)
    keyList.sort()
    lettersList.sort()
    if keyList != lettersList:
        errmsg = 'There is an error in the key or symbol set.'
        raise PyExpSyntaxException(errmsg)

def getBlankCipherletterMapping():
    letterMapping = {
    'A': [], 'B': [], 'C': [], 'D': [], 'E': [], 'F': [], 'G': [],\
    'H': [], 'I': [], 'J': [], 'K': [], 'L': [], 'M': [], 'N': [], 'O': [],\
    'P': [], 'Q': [], 'R': [], 'S': [], 'T': [], 'U': [], 'V': [], 'W': [],\
    'X': [], 'Y': [], 'Z': []
    }
    return letterMapping

def addLettersToMapping(letterMapping, cipherword, candidate):

    letterMapping = copy.deepcopy(letterMapping)
    for i in range(len(cipherword)):
        if candidate[i] not in letterMapping[cipherword[i]]:
            letterMapping[cipherword[i]].append(candidate[i])
    return letterMapping

def intersectMapping(mapA, mapB):
    intersectMapping = getBlankCipherletterMapping()
    for letter in UPPERLETTERS:
        if mapA[letter] == []:
            intersectMapping[letter] = copy.deepcopy(mapB[letter])
        elif mapB[letter] == []:
            intersectMapping[letter] = copy.deepcopy(mapA[letter])
        else:
            for mappedLetter in mapA[letter]:
                if mappedLetter in mapB[letter]:
                    intersectMapping[letter].append(mappedLetter)

    return intersectMapping

def removeSolvedLettersFromMapping(letterMapping):

    letterMapping = copy.deepcopy(letterMapping)
    loopAgain = True
    while loopAgain:
        loopAgain = False

        solvedLetters = []
        for cipherletter in UPPERLETTERS:
            if len(letterMapping[cipherletter]) == 1:
                solvedLetters.append(letterMapping[cipherletter][0])

        for cipherletter in UPPERLETTERS:
            for s in solvedLetters:
                if len(letterMapping[cipherletter]) != 1 and s in letterMapping[cipherletter]:
                    letterMapping[cipherletter].remove(s)
                    if len(letterMapping[cipherletter]) == 1:
                        loopAgain = True

    return letterMapping

def getLetterMap(message):
    intersectedMap = getBlankCipherletterMapping()
    cipherwordList = nonLettersOrSpacePattern.sub('', message.upper()).split()
    for cipherword in cipherwordList:
        newMap = getBlankCipherletterMapping()

        wordPattern = getWordPattern(cipherword)
        allPattern = getFullPatterns()
        if wordPattern not in allPattern:
            continue
        for candidate in allPattern[wordPattern]:
            newMap = addLettersToMapping(newMap, cipherword, candidate)

        intersectedMap = intersectMapping(intersectedMap, newMap)

    return removeSolvedLettersFromMapping(intersectedMap)

def cipher(message, key, mode):

    translated = ''
    charsA = UPPERLETTERS
    charsB = key
    if mode == 'decrypt':
        charsA, charsB = charsB, charsA

    for symbol in message:
        if symbol.upper() in charsA:
            symIndex = charsA.find(symbol.upper())
            if symbol.isupper():
                translated += charsB[symIndex].upper()
            else:
                translated += charsB[symIndex].lower()
        else:
            translated += symbol

    return translated

def bruter(message):
    msg = "Establishing letterMap..."
    logger.info(msg)
    letterMapping = getLetterMap(message)
    msg = "[+] Possible letterMap: \n"
    dataToStdout(msg)
    pprint.pprint(letterMapping)
    msg = "letterMap established successfully."
    logger.info(msg)
    key = ['x'] * len(UPPERLETTERS)
    for cipherletter in UPPERLETTERS:
        if len(letterMapping[cipherletter]) == 1:
            keyIndex = UPPERLETTERS.find(letterMapping[cipherletter][0])
            key[keyIndex] = cipherletter
        else:
            message = message.replace(cipherletter.lower(), '_')
            message = message.replace(cipherletter.upper(), '_')
    key = ''.join(key)

    result = {}

    result[key] = cipher(message, key, 'decrypt')

    return result

