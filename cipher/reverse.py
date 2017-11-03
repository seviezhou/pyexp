
def cipher(message, key, mode):
    i = len(message) - 1
    translated = ''

    while i >= 0:
        translated = translated + message[i]
        i -= 1
    return translated