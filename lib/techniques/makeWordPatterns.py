from lib.core.data import paths

def getWordPattern(word):

    word = word.upper()
    nextNum = 0
    letterNum = {}
    wordPattern = []

    for letter in word:
        if letter not in letterNum:
            letterNum[letter] = str(nextNum)
            nextNum += 1
        wordPattern.append(letterNum[letter])

    return '.'.join(wordPattern)

def getFullPatterns():
    allPatterns = {}
    f = open(paths.COMMON_ENGLISH_WORDS)
    wordlist = f.read().split('\n')
    f.close()

    for word in wordlist:
        pattern = getWordPattern(word)
        if pattern not in allPatterns:
            allPatterns[pattern] = [word]
        else:
            allPatterns[pattern].append(word)

    return allPatterns