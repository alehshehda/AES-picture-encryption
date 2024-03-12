# SZYFROWANIE OBRAZKU ZA POMOCA AES

# import komendy
from modules.encyptionLogic import encryptFile
from modules.decryptionLogic import bruteForceDecrypt, decryptFile
import os
import sys
from PIL import Image
import numpy as np
from skimage.metrics import structural_similarity as ssim


# porownanie dwoch plikow czy sa podobne
# Structural Similarity Index Measurement
# conwertacja 'L' do "grayscale" dla prawidlowego porownywania zaszyfrowanego i deszyfrowanego pliku
# zwraca liczbe 0-1, reprezentującą pdoobienstwo obrazkow
def calculateSsim(originalPath, decryptedPath):
    originalImage = np.array(Image.open(originalPath).convert('L'))
    decryptedImage = np.array(Image.open(decryptedPath).convert('L'))
    ssimIndex, _ = ssim(originalImage, decryptedImage, full=True)
    return ssimIndex


if __name__ == '__main__':

    # inicjalizacja lokalizacji plikow
    inputFileOriginal = "C:/Users/alehs/Pictures/pythonRes/original.png"
    outputFileEncrypted = "C:/Users/alehs/Pictures/pythonRes/encrypted.bin"
    outputFileDecrypted = "C:/Users/alehs/Pictures/pythonRes/decrypted.png"
    outputFileDecryptedBruteForce = "C:/Users/alehs/Pictures/pythonRes/decryptedBruteForce.png"

    password = input("Input password for the key to generate: ")

    # sprawdzanie czy haslo nie jest puste
    if not password:
        print("Password cannot be empty. Exiting.")
        sys.exit(1)

    # dla przykladowego zlamania brute-force
    originalKey = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x0c'

    # rzeczywista generacja
    # originalKey = generateKey(password)
    # print("original key: ", originalKey)

    # szyfrowanie obrazka
    encryptFile(inputFileOriginal, outputFileEncrypted, originalKey)

    # 'proba' zlamania
    decryptKey = bruteForceDecrypt(outputFileEncrypted, outputFileDecryptedBruteForce, inputFileOriginal)

    # jezeli jedna z prob udana, to przepisujemy zawartosc z postaci binarnej do png
    if decryptKey:
        decryptFile(outputFileEncrypted, outputFileDecrypted, decryptKey)
        os.remove(outputFileDecryptedBruteForce)
    else:
        print("Decryption failed. Unable to find the correct key.")
