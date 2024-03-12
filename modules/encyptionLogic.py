import secrets
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES


# generowanie randomowego seed'a
def generateSeed():
    seed = secrets.token_bytes(16)
    return seed


# generowanie klucza za pomoca zgenerowanego seeda i hasla
# zgenerowany klucz ma dlugosc 16(128 bitow)
def generateKey(encryptionPassword):
    seed = generateSeed()
    key = PBKDF2(encryptionPassword, seed, dkLen=16, count=1000000)
    return key


# szyfrowanie pliku za pomoca zgenerowanego klucza i metody AES(advanced Encryption Standard)
def encryptFile(FileOriginal, FileEncrypted, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(FileOriginal, 'rb') as file:  # odczyt pliku w binarnej postaci
        plainText = file.read()

    cipherText, tag = cipher.encrypt_and_digest(plainText)  # szyfrowanie informacji

    with open(FileEncrypted, 'wb') as file:  # zapisywanie w postaci binarnej zaszyfrowanej informacji
        file.write(cipher.nonce)  # zeby uniknac powtornego uzywania parametrow szyfrowania
        file.write(tag)  # kod dla upewnienia integracji zaszyfrowanej daty
        file.write(cipherText)
        print("File has been encrypted successfully in the .bin format.")
