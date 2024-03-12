import sys
import time
import itertools
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from skimage.metrics import structural_similarity as ssim


# constanty
TAG_SIZE = 16
SSIM_THRESHOLD = 0.99


# generowanie wszytkich kluczy i podbieranie prawidlowego dla deszyfracji
# zwraca None lub klucz do deszyfracji jezeli jest prawidłowy
def bruteForceDecrypt(FileEncrypted, FileDecryptedBruteForce, FileOriginal):

    with open(FileEncrypted, 'rb') as file:
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
        # dla bardziej przyjemnej percepcji
        dots = '.' * ((int(time.time()) % 3) + 1)
        sys.stdout.write("\rAttempting key for the decryption: {0} {1}".format(candidateKey.hex(), dots))
        sys.stdout.flush()

        cipher = AES.new(candidateKey, AES.MODE_EAX, nonce=nonce)
        try:
            # probujemy deszyfrowac
            decryptedData = cipher.decrypt(encryptedData)
            cipher.verify(tag)  # werifikujemy tag

            # wpisujemy do pliku oraz porownujemy poprawnosc deszyfracji
            with open(FileDecryptedBruteForce, 'wb') as file:
                file.write(decryptedData)
                ssimIndex = calculateSsim(FileOriginal, FileDecryptedBruteForce)
                if ssimIndex >= SSIM_THRESHOLD:
                    print("\rDecryption successful with key:", candidateKey.hex())
                    print("Decrypted image is a correct file, accuracy of decryption is: ", ssimIndex * 100, "%")
                    return bytes(candidateKey)

        except ValueError as e:
            pass

    # If no key is found
    print("Brute-force decryption unsuccessful.")
    return None


# porownanie dwoch plikow czy sa podobne
# Structural Similarity Index Measurement
# conwertacja 'L' do "grayscale" dla prawidlowego porownywania zaszyfrowanego i deszyfrowanego pliku
# zwraca liczbe 0-1, reprezentującą pdoobienstwo obrazkow
def calculateSsim(originalPath, decryptedPath):
    originalImage = np.array(Image.open(originalPath).convert('L'))
    decryptedImage = np.array(Image.open(decryptedPath).convert('L'))
    ssimIndex, _ = ssim(originalImage, decryptedImage, full=True)
    return ssimIndex


# przyjmuje klucz z brute-force i deszyfruje plik w png formacie
def decryptFile(FileEncrypted, FileDecrypted, key):
    with open(FileEncrypted, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(TAG_SIZE)
        cipherText = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    plainText = cipher.decrypt_and_verify(cipherText, tag)

    with open(FileDecrypted, 'wb') as file:
        file.write(plainText)

    print("File has been decrypted successfully and saved in .png format.")
