import math

from lib.core.data import logger

def cipher(message, key, mode):

    key = int(key)

    if mode == 'encrypt':
        ciphertext = [''] * key
        for col in range(key):
            pointer = col
            while pointer < len(message):
                ciphertext[col] += message[pointer]
                pointer += key
        return ''.join(ciphertext)

    elif mode == 'decrypt':
        numOfColumns = math.ceil(len(message) / key)
        numOfRows = key
        numOfShadedBoxes = (numOfColumns *  numOfRows) - len(message)
        plaintext = [''] * numOfColumns
        col = 0
        row = 0
        for symbol in message:
            plaintext[col] += symbol
            col += 1
            if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
                col = 0
                row += 1
        return ''.join(plaintext)
    else:
        return None

def bruter(message):

    result = {}

    for key in range(1, len(message)):

        PossibleText = cipher(message, key, "decrypt")

        result[key] = PossibleText

    return result


# def transpositionFileCipher(inputfile, outputfile, key, mode):
#     inputFilename = inputfile
#     outputFilename = outputfile
#     if not os.path.exists(inputFilename):
#         pass
#         sys.exit(1)
#     file = open(inputFilename)
#     content = file.read()
#     file.close()
#     startTime = time.time()
#     translated = transpositionCipher(content, key, mode)
#     totalTime = round(time.time() - startTime, 5)
#     print("work with one file done in %s seconds" % totalTime)
#     outfile = open(outputFilename, 'w')
#     outfile.write(translated)
#     outfile.close()
#     print("result written to outputfile: %s" % os.path.realpath(outputFilename))

