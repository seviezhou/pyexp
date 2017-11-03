"""
used to detect if a sentence is an english sentence
"""

from lib.core.data import conf
from lib.core.data import paths
from lib.core.settings import LETTERS_AND_SPACE

def loadDictionary():
    dictionaryFile = open(paths.COMMON_ENGLISH_WORDS)
    englishWords = {}
    for word in dictionaryFile.read().split('\n'):
        englishWords[word] = None
    dictionaryFile.close()
    return englishWords

def removeNonLetters(message):
    lettersList = []
    for symbol in message:
        if symbol in LETTERS_AND_SPACE:
            lettersList.append(symbol)
    return ''.join(lettersList)

def getEnglishCount(message):
    message = message.upper()
    message = removeNonLetters(message)
    possibleWords = message.split()
    if possibleWords == []:
        return 0.0

    match = 0
    for word in possibleWords:
        if word in conf.englishWords:
            match += 1
    return float(match) / len(possibleWords)

def isEnglish(message, wordPercentage=20, letterPercentage=85):
    wordsMatch = getEnglishCount(message) * 100 >= wordPercentage
    numLetters = len(removeNonLetters(message))
    messageLettersPercentage = float(numLetters) / len(message) * 100
    lettersMatch = messageLettersPercentage >= letterPercentage
    return wordsMatch and lettersMatch