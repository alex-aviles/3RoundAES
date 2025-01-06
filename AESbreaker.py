# Alexander Aviles - CSE 468 Final Credit
# Usage: python3 AESbreaker.py
from filehandler import *

# SBoxDDTOccurences function to produce difference distribution occurrences table
def SBoxDDTOccurrences():
    table = [[]] * 256
    for i in range(256):
        for j in range(256):
            diff = i ^ j
            newDiff = SBoxList[i] ^ SBoxList[j]
            if len(table[diff]) != 0:
                table[diff][newDiff] += 1
            else:
                table[diff] = [0] * 256
                table[diff][newDiff] = 1
    return table

# SBoxDDTLookup function to produce differences distribution lookup table
def SBoxDDTLookup():
    table = {}
    for i in range(256):
        for j in range(256):
            diff = i ^ j
            newDiff = SBoxList[i] ^ SBoxList[j]
            if diff in table:
                if newDiff not in table[diff]:
                    table[diff].append(newDiff)
            else:
                table[diff] = [newDiff]
    return table

ddt = SBoxDDTLookup()

# stateToText function to convert 4x4 state to ascii text
def stateToText(state: list) -> ascii:
    state = [state[row][col] for col in range(4) for row in range(4)]
    text = ''.join(chr(byte) for byte in state)
    return text

# generateImpossibleStates function uses provided different to generate list of impossible states 
def generateImpossibleStates(differential: bytes) -> list:
    differentials = []
    for index in range(4):
        differentials.append([])
        for byte in range(256):
            if byte not in ddt[differential[index]]:
                differentials[index].append(byte)

    impossibleStates = []
    for index in range(4):
        for diff in differentials[index]:
            possibleState = bytesToState((b'\x00' * index) + bytes([diff]) + (b'\x00' * (15 - index)))
            secondState = ShiftRows(possibleState)
            thirdState = MixColumns(secondState)
            impossibleStates.append(stateToBytes(thirdState))
    return impossibleStates

# stateXOR function to perform byte by byte xor between states
def stateXOR(first: list, second: list) -> bytes:
    return bytes(first[i] ^ second[i] for i in range(len(first)))

# firstRoundSequence performs 1 round AES operations on provided 4x4 state
def firstRoundSequence(state: list) -> list:
    state = bytesToState(state)
    firstState = SubBytes(state)
    secondState = ShiftRows(firstState)
    thirdState = MixColumns(secondState)
    fourthState = stateToBytes(thirdState)
    return fourthState

# ReverseState function to take the provided key and 4x4 state and do the opposite of firstRoundSequence without MixColumns
def ReverseState(state: list, key: bytes) -> list:
    state = bytesToState(state)
    key = bytesToState(key)
    firstState = AddRoundKey(state, key)
    secondState = InverseShiftRows(firstState)
    thirdState = InverseSubBytes(secondState)
    fourthState = stateToBytes(thirdState)
    return fourthState

# generateKeys function uses all alpha-beta pairs to generate possible keys
def generateKeys(abPairs: list) -> list:
    impossibleKeys = [None] * 256
    byteArray = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    
    for byte in range(256):
        impossibleKeys[byte] = [None] * 16
        for plaintextA, plaintextB, ciphertextA, ciphertextB in abPairs:
            roundKey = bytes([byte]) + (b'\x00' * 15)
            plainA = stateXOR(plaintextA, roundKey)
            plainB = stateXOR(plaintextB, roundKey)
            conversionA = firstRoundSequence(plainA)
            conversionB = firstRoundSequence(plainB)
            abDifferential1 = stateXOR(conversionA, conversionB)
            impossibleState = generateImpossibleStates(abDifferential1)

            for index in range(16):
                if impossibleKeys[byte][index] is None:
                    impossibleKeys[byte][index] = []
                choice = byteArray[index]
                for key in range(256):
                    if key in impossibleKeys[byte][index]:
                        continue
                    check = (b'\x00' * index) + bytes([key]) + (b'\x00' * (15-index))
                    cipherA = ReverseState(ciphertextA, check)
                    cipherB = ReverseState(ciphertextB, check)
                    abDifferential2 = stateXOR(cipherA, cipherB)
                    for state in impossibleState:
                        if abDifferential2[choice] == state[choice]:
                            impossibleKeys[byte][index].append(key)
        roundKeys = []
        for possible in range(16):
            roundKeys.append(len(impossibleKeys[byte][possible]))
        if 256 not in roundKeys:
            possibleKey = byte
            break
    keys = impossibleKeys[possibleKey]
    return keys

# generateByteRange function creates list of 0x0-0xff bytes
def generateByteRange():
    byteList = []
    for byte in range(256):
        byteList.append(byte)
    return byteList

# InverseKeyExpansion function performs reverse of KeyExpansion function
def InverseKeyExpansion(key: bytes, rounds: int) -> bytes:
    roundKeys = [key]
    for round in range(rounds, 0, -1):
        current = roundKeys[0]
        previous = [None] * 4
        
        previous[3] = stateXOR(current[12:], current[8:12])
        previous[2] = stateXOR(current[8:12], current[4:8])
        previous[1] = stateXOR(current[4:8], current[:4])
        
        value = Rcon(round)
        word = SubWord(RotWord(previous[3]))
        previous[0] = stateXOR(word, stateXOR(value, current[:4]))
        previousKey = (previous[0] + previous[1] + previous[2] + previous[3])
        roundKeys.insert(0, previousKey)
        
    print(f"InverseKeyExpansion returning {previousKey}")
    return previousKey

# AESattack function takes alpha-beta pairs, possible keys, and number of rounds to determine key used to encrypt ciphertext
def AESattack(abPairs: list, keys: list, numOfRounds: int) -> bytes:
    possibleKeys = []
    byteList = generateByteRange()
    for key in keys:
        possibleKeys.append(list(set(byteList) - set(key)))
    
    def keyCombos(possibleKeys, index=0, current=[]):
        if index == len(possibleKeys):
            yield current
            return
        for value in possibleKeys[index]:
            yield from keyCombos(possibleKeys, index + 1, current + [value])

    progressKeys = keyCombos(possibleKeys)
    match = abPairs[0][2]
    for key in progressKeys:
        actualKey = InverseKeyExpansion(list(key), numOfRounds)
        decrypted = decrypt(match, actualKey, numOfRounds)
        if decrypted == abPairs[0][0]:
            break

    print(f"AESattack returning {actualKey}")
    return actualKey

# runAESbreaker function generates 10 alpha-beta pairs from plain/cipher texts and prints the broken AES key used to encrypt the ciphertexts
def runAESbreaker():
    numOfPairs = 10
    plaintexts = storePlaintexts(numOfPairs)
    ciphertexts = storeCiphertexts(numOfPairs)
    abPairs = createABPairs(plaintexts, ciphertexts)
    print("Cracking AES Key...")
    keys = generateKeys(abPairs)
    numOfRounds = 3
    theKey = AESattack(abPairs, keys, numOfRounds)
    print("Broken AES Key = ", theKey)
    
# decryptFile function takes ciphertext, key, and number of rounds and decrypts the text using ECB and writes the bytes to plaintextFile
def decryptFile(ciphertextFile: ascii, key: bytes, numOfRounds: int, plaintextFile: ascii):
    with open(ciphertextFile, "rb") as cipher:
        ciphertext = cipher.read()

    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        ecbSet = decrypt(block, key, numOfRounds)
        plaintext += stateToBytes(ecbSet)

    with open(plaintextFile, "wb") as plain:
        plain.write(plaintext)

    print(f"Decryption complete. Plaintext is {plaintextFile}.")


#numOfRounds = 3
#
#key = bytes.fromhex("457e153128aed2ccabf715f109cf63e9")
#plaintext = textToState("ThisIsPlaintext")
#ciphertext = encrypt(plaintext, key, numOfRounds)
#cipher = stateToText(ciphertext)
#print(f"Ciphertext = {cipher}")
#decrypted = decrypt(ciphertext, key, numOfRounds)
#newPlaintext = stateToText(decrypted)
#print(f"Plaintext = {newPlaintext}")
#
#runAESbreaker()

#key = b"atari2600**4life"
#realCiphertext = "part4ciphertext.bin"
#finalPlaintext = "decrypted.bin"
#decryptFile(realCiphertext, key, numOfRounds, finalPlaintext)