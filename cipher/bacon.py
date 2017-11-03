def cipher(message, key, mode):

    message = message.replace('A','0').replace('B','1')

    return ''.join(chr(int(message[i: i + 5],2) + 97) for i in range(0, len(message) - 4, 5))
