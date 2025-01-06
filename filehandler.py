# Alexander Aviles - CSE 468 Final Credit
import os
from AESencryption import *
from AESdecryption import *

# stateToBytes function to convert 4x4 state to byte sequence
def stateToBytes(state: list) -> bytes:
    stateBytes = bytes(sum(state, []))
    return stateBytes

# createPlaintexts function to create count number of 16 byte plaintexts     
def createPlaintexts(count: int):
    plaintexts = createActiveBytes(count)
    for text, plaintext in enumerate(plaintexts):
        file = f"plaintexts/plaintext{text}.bin"
        with open(file, "wb") as binary:
            binary.write(plaintext)

# createActiveBytes helper function for createPlaintexts
def createActiveBytes(count: int):
    while True:
        unique = True
        uniqueBytes = []
        for c in range(count):
            uniqueBytes.append(os.urandom(1))            
        inactive = []
        for c in range(count - 1):
            for b in range(c + 1, count):
                xor = uniqueBytes[c][0] ^ uniqueBytes[b][0]
                if xor not in inactive:
                    inactive.append(xor)
                else:
                    unique = False
        if unique:
            fileBytes = [bytes(uniqueBytes[c]) + (b'\x00' * 15) for c in range(count)]
            return fileBytes
    return NULL
 
# createCiphertexts function to encrypt each plaintext file with given key for given number of rounds        
def createCiphertexts(key, numOfRounds):
    files = sorted(os.listdir("plaintexts"))
    for filename in files:
        path = f"plaintexts/{filename}"
        with open(path, "rb") as file:
            plaintext = file.read()
        state = bytesToState(plaintext)
        ciphertext = encrypt(state, key, numOfRounds)
        ciphertext = stateToBytes(ciphertext)
        cipherPath = f"ciphertexts/ciphertext{filename[9:-4]}.bin"
        with open(cipherPath, "wb") as cipherFile:
            cipherFile.write(ciphertext)
        print(f"Encrypted {filename} -> {os.path.basename(cipherPath)}")

# removeFiles function to delete all plaintext or ciphertext files in provided directory
def removeFiles(count: int, directory: ascii):
    for c in range(count):
        file = os.path.join(directory, f"plaintext{c}.bin")
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed: {file}")
        else:
            print(f"File not found: {file}")

# storePlaintexts function to get plaintexts from directory into variable list            
def storePlaintexts(pairCount: int) -> list:
    plaintexts = []
    for i in range(pairCount):
        file = f"plaintexts/plaintext{i}.bin"
        with open(file, "rb") as binary:
            plaintext = binary.read()
            plaintexts.append(plaintext)
    return plaintexts

# storeCiphertexts function to get ciphertexts from directory into variable list         
def storeCiphertexts(pairCount: int) -> list:
    ciphertexts = []
    for i in range(pairCount):
        file = f"ciphertexts/plaintext{i}.bin.enc"
        with open(file, "rb") as binary:
            ciphertext = binary.read()
            ciphertexts.append(ciphertext)
    return ciphertexts
            
# create list of alpha-beta pairs between plain and cipher texts            
def createABPairs(plaintexts: list, ciphertexts: list) -> list:
    abPairs = []
    count = len(plaintexts)
    for first in range(count - 1):
        for second in range(first + 1, count):
            plainA = plaintexts[first]
            plainB = plaintexts[second]
            cipherA = ciphertexts[first]
            cipherB = ciphertexts[second]
            abPairs.append([plainA, plainB, cipherA, cipherB])
    return abPairs