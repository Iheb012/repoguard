import base64
import os

import requests


def decode_upload(blob):
    return base64.b64decode(blob)  # decoding alone is normal


def run(model):
    model.eval()  # PyTorch, not the builtin
    port = os.environ.get("PORT", "8000")
    if "DEBUG" in os.environ:
        print("debug on")
    return requests.get("https://api.example.test/items"), port
