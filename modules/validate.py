import hashlib
import os
import re

from dotenv import load_dotenv


def api_key():
    load_dotenv()
    api_key = os.getenv("VIRUSTOTAL_APIKEY")
    if not api_key:
        print(
            f'\nNo API key found in .\.env\n'
        )
        exit(1)


def file(path):
    hasher = hashlib.sha256()
    exists = os.path.isfile(path)
    if exists:
        with open(path, 'rb') as bin:
            hasher.update(bin.read())
            return hasher.hexdigest()
    else:
        print(
            f'\nFILE not found.\n'
        )
        exit(1)


def hash(hash):
    sha1_pattern = r'^[a-f0-9]{40}$'
    sha256_pattern = r'^[a-f0-9]{64}$'
    md5_pattern = r'^[a-f0-9]{32}$'
    for pattern in [sha1_pattern, sha256_pattern, md5_pattern]:
        if re.match(pattern, hash.lower()):
            return True
    print(
        f'\nHASH type selected with invalid hash format.\n'
    )
    exit(1)


def url(url):
    pattern = r'(www|http:|https:)+[^\s]+[\w]'
    if not re.match(pattern, url):
        print(
            f'\nURL type selected with invalid url format.\n'
        )
        exit(1)
    return True
        


