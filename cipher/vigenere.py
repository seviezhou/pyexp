from lib.techniques.detectEnglish import isEnglish
from lib.techniques.freqAnalysis import englishFreqMatchScore
from lib.core.settings import UPPERLETTERS
from lib.core.settings import NONLETTERS_PATTERN
from lib.core.common import dataToStdout

import itertools

MAX_KEY_LENGTH = 16

NUM_MOST_FREQ_LETTERS = 4

def findRepeatSequencesSpacings(message):

    message = NONLETTERS_PATTERN.sub('', message.upper())

    seqSpacings = {}

    for seqLen in range(3, 6):
        for seqStart in range(len(message) - seqLen):
            seq = message[seqStart:seqStart + seqLen]

            for i in range(seqStart + seqLen, len(message) - seqLen):
                if message[i:i + seqLen] == seq:
                    if seq not in seqSpacings:
                        seqSpacings[seq] = []

                    seqSpacings[seq].append(i - seqStart)
    return seqSpacings

def getUsefulFactors(num):

    if num < 2:
        return []

    factors = []
    for i in range(2, MAX_KEY_LENGTH + 1):
        if num % i == 0:
            factors.append(i)
            factors.append(int(num / i))

    if 1 in factors:
        factors.remove(1)

    return list(set(factors))

def getItemAtIndexOne(x):
    return x[1]

def getMostCommonFactors(seqFactors):

    factorCounts = {}

    for seq in seqFactors:
        factorlist = seqFactors[seq]
        for factor in factorlist:
            if factor not in factorCounts:
                factorCounts[factor] = 0
            factorCounts[factor] += 1
    factorByCount = []
    for factor in factorCounts:
        if factor <= MAX_KEY_LENGTH:
            factorByCount.append((factor, factorCounts[factor]))
    factorByCount.sort(key=getItemAtIndexOne, reverse=True)

    return factorByCount

def kasiskiExamination(ciphertext):

    repeatedSeqSpacings = findRepeatSequencesSpacings(ciphertext)

    seqFactors = {}

    for seq in repeatedSeqSpacings:
        seqFactors[seq] = []
        for spacing in repeatedSeqSpacings[seq]:
            seqFactors[seq].extend(getUsefulFactors(spacing))

    factorByCount = getMostCommonFactors(seqFactors)

    allLikelyKeyLengths = []

    for twoIntTuple in factorByCount:
        allLikelyKeyLengths.append(twoIntTuple[0])

    return allLikelyKeyLengths

def getNthSubkeysLetters(n, keyLength, message):

    message = NONLETTERS_PATTERN.sub('', message.upper())

    letters = []

    for i in range(n - 1, len(message), keyLength):
        letters.append(message[i])

    return ''.join(letters)

def attemptHackWithKeyLength(ciphertext, mostLikelyKeyLength):

    ciphertextUp = ciphertext.upper()

    allFreqScores = []

    for nth in range(1, mostLikelyKeyLength + 1):
        nthLetters = getNthSubkeysLetters(nth, mostLikelyKeyLength, ciphertextUp)
        freqScores = []
        for key in UPPERLETTERS:
            decryptedText = cipher(nthLetters, key, 'decrypt')

            keyAndFreqMatchTuple = (key, englishFreqMatchScore(decryptedText))

            freqScores.append(keyAndFreqMatchTuple)

        freqScores.sort(key=getItemAtIndexOne, reverse=True)
        allFreqScores.append(freqScores[:NUM_MOST_FREQ_LETTERS])

    for i in range(len(allFreqScores)):
        FreqScoresStr = ''
        for freq in allFreqScores[i]:
            FreqScoresStr += freq[0]
            FreqScoresStr += ' '
        msg = '[+] Possible letters for letter %d of the key: %s\n' % (i + 1, FreqScoresStr)
        dataToStdout(msg)

    first = True

    for indexes in itertools.product(range(NUM_MOST_FREQ_LETTERS), repeat=mostLikelyKeyLength):

        possiblekey = ''

        for i in range(mostLikelyKeyLength):

            possiblekey += allFreqScores[i][indexes[i]][0]

        if first:
            msg = '\033[33mAttempting with key: %s\n' % (possiblekey)
            dataToStdout(msg)
            first = False
        else:
            msg = '\033[33m\033[1AAttempting with key: %s\033[0m\n' % (possiblekey)
            dataToStdout(msg)

        decryptedText = cipher(ciphertextUp, possiblekey, 'decrypt')
        if isEnglish(decryptedText):
            origCase = []
            for i in range(len(ciphertext)):
                if ciphertext[i].isupper():
                    origCase.append(decryptedText[i].upper())
                else:
                    origCase.append(decryptedText[i].lower())
            decryptedText = ''.join(origCase)
            return {possiblekey : decryptedText}

    return None

def cipher(message, key, mode):
    translated = []
    keyIndex = 0
    key = key.upper()

    for symbol in message:
        num = UPPERLETTERS.find(symbol.upper())
        if num != -1:
            if mode == 'encrypt':
                num += UPPERLETTERS.find(key[keyIndex])
            elif mode == 'decrypt':
                num -= UPPERLETTERS.find(key[keyIndex])

            num %= len(UPPERLETTERS)

            if symbol.isupper():
                translated.append(UPPERLETTERS[num])
            elif symbol.islower():
                translated.append(UPPERLETTERS[num])

            keyIndex += 1
            if keyIndex == len(key):
                keyIndex = 0
        else:
            translated.append(symbol)

    return ''.join(translated)


def bruter(message):

    hackedMessageDict = None

    allLikelyKeyLengths = kasiskiExamination(message)

    keyLengthStr = ''
    for keyLength in allLikelyKeyLengths:
        keyLengthStr += '%s ' % (keyLength)

    if len(keyLengthStr) != 0:
        msg = '[+] Kasiski Examination results indicate the most likely key lengths are: %s\n' % keyLengthStr
        dataToStdout(msg)

    for keyLength in allLikelyKeyLengths:
        msg = '[+] Attempting hack with key length %s (%s possible keys)...\n' % (keyLength, NUM_MOST_FREQ_LETTERS ** keyLength)
        dataToStdout(msg)
        hackedMessageDict = attemptHackWithKeyLength(message, keyLength)

        if hackedMessageDict != None:
            break

    if hackedMessageDict == None:
       msg = '[-] Unable to hack message with likely key length(s)\n'
       dataToStdout(msg)
       answer = input("Do you want to brute forcing key length?(y/n): ")
       for keyLength in range(1, MAX_KEY_LENGTH + 1):
            if keyLength not in allLikelyKeyLengths:
                msg = '[+] Attempting hack with key length %s (%s possible keys)...\n' % (keyLength, NUM_MOST_FREQ_LETTERS ** keyLength)
                dataToStdout(msg)
                hackedMessageDict = attemptHackWithKeyLength(message, keyLength)
                if hackedMessageDict != None:
                    break
    return hackedMessageDict