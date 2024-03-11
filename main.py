#SZYFROWANIE OBRAZKU ZA POMOCA AES

from Crypto.Protocol.KDF import PBKDF2
import secrets
from Crypto.Cipher import AES
from skimage.metrics import structural_similarity as ssim
from PIL import Image
import numpy as np
import os
import sys
import time
import itertools

# constanty
SSIM_THRESHOLD = 0.99
TAG_SIZE = 16


# generowanie randomowego seeda
def generateSeed():
    seed = secrets.token_bytes(16)
    return seed


# generowanie klucza za pomoca zgenerowanego seeda i hasla
# zgenerowany klucz ma dlugosc 16(128 bitow)
def generateKey(password):
    seed = generateSeed()
    key = PBKDF2(password, seed, dkLen=16, count=1000000)
    return key


# porownanie dwoch plikow czy sa podobne
# Structural Similarity Index Measurement
# conwertacja 'L' do "grayscale" dla prawidlowego porownywania zaszyfrowanego i deszyfrowanego pliku
def calculateSsim(originalPath, decryptedPath):
    originalImage = np.array(Image.open(originalPath).convert('L'))
    decryptedImage = np.array(Image.open(decryptedPath).convert('L'))
    ssimIndex, _ = ssim(originalImage, decryptedImage, full=True)
    return ssimIndex


# szyfrowanie pliku za pomoca zgenerowanego klucza i metody AES(advanced Encryption Standard)
def encryptFile(inputFileOriginal, outputFileEncrypted, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(inputFileOriginal, 'rb') as file:  # czytanie pliku w binarnej postaci
        plainText = file.read()

    cipherText, tag = cipher.encrypt_and_digest(plainText)  # szyfrowanie informacji

    with open(outputFileEncrypted, 'wb') as file:  # zapisywanie w postaci binarnej zaszyfrowanej informacji
        file.write(cipher.nonce)  # zeby uniknac powtornego uzywania parametrow szyfrowania
        file.write(tag)  # kod dla upewnienia integracji zaszyfrowanej daty
        file.write(cipherText)
        print("File has been encrypted successfully in the .bin format.")


# generowanie wszytkich kluczy i podbieranie prawidlowego dla deszyfracji
def bruteForceDecrypt(outputFileEncrypted, outputFileDecryptedBruteForce, inputFileOriginal):

    with open(outputFileEncrypted, 'rb') as file:
        encryptedData = file.read()

    # pobieramy nonce i tag z zaszyfrowanego pliku
    nonce = encryptedData[:16]
    tag = encryptedData[16:16 + TAG_SIZE]
    encryptedData = encryptedData[16 + TAG_SIZE:]

    # generujemy wszystkie mozliwe kluczy
    keySize = 16  # 128 bitow dla AES
    allPossibleKeys = itertools.product(range(256), repeat=keySize)

    # probujemy kazda wartosc
    for candidateKey in allPossibleKeys:
        candidateKey = bytes(candidateKey)
        dots = '.' * ((int(time.time()) % 3) + 1)
        sys.stdout.write("\rAttempting key for the decryption: {0} {1}".format(candidateKey.hex(), dots))
        sys.stdout.flush()

        cipher = AES.new(candidateKey, AES.MODE_EAX, nonce=nonce)
        try:
            # probujemy deszyfrowac
            decryptedData = cipher.decrypt(encryptedData)
            cipher.verify(tag)  # werifikujemy tag

            # wpisujemy do pliku oraz porownujemy poprawnosc deszyfracji
            with open(outputFileDecryptedBruteForce, 'wb') as file:
                file.write(decryptedData)
                ssimIndex = calculateSsim(inputFileOriginal, outputFileDecryptedBruteForce)
                if ssimIndex >= SSIM_THRESHOLD:
                    print("\rDecryption successful with key:", candidateKey.hex())
                    print("Decrypted image is a correct file, accuracy of decryption is: ", ssimIndex * 100, "%")
                    return bytes(candidateKey)

        except ValueError as e:
            pass

    # If no key is found
    print("Brute-force decryption unsuccessful.")
    return None

# przyjmuje klucz z brute-force i deszyfruje plik w png formacie
def decryptFile(outputFileEncrypted, outputFileDecrypted, key):
    with open(outputFileEncrypted, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(TAG_SIZE)
        cipherText = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    plainText = cipher.decrypt_and_verify(cipherText, tag)

    with open(outputFileDecrypted, 'wb') as file:
        file.write(plainText)

    print("File has been decrypted successfully and saved in .png format.")



if __name__ == '__main__':
    inputFileOriginal = "C:/Users/alehs/Pictures/pythonRes/original.png"
    outputFileEncrypted = "C:/Users/alehs/Pictures/pythonRes/encrypted.bin"
    outputFileDecrypted = "C:/Users/alehs/Pictures/pythonRes/decrypted.png"
    outputFileDecryptedBruteForce = "C:/Users/alehs/Pictures/pythonRes/decryptedBruteForce.png"

    password = input("Input password for the key to generate: ")

    # zeby haslo nie bylo puste
    if not password:
        print("Password cannot be empty. Exiting.")
        sys.exit(1)

    originalKey = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x0c'
    #originalKey = generateKey(password)
    #print("original key: ", originalKey)

    encryptFile(inputFileOriginal, outputFileEncrypted, originalKey)

    generatedKey = bruteForceDecrypt(outputFileEncrypted, outputFileDecryptedBruteForce, inputFileOriginal)

    if generatedKey:
        decryptFile(outputFileEncrypted, outputFileDecrypted, generatedKey)
        os.remove(outputFileDecryptedBruteForce)
    else:
        print("Decryption failed. Unable to find the correct key.")
