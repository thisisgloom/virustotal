import base64
import os
from sys import exit

import requests


URLS_BASE = "https://www.virustotal.com/api/v3/urls/"
FILE_BASE = "https://www.virustotal.com/api/v3/files/"


def check_api_err(resp):
    if "error" in resp.keys():
        if resp["error"]["code"] == "NotFoundError":
            print(
                f'\nFile hash not found in the VT database.\n'
            )
            exit(1)
        else:    
            print(
                f'\nError response received from the api:\n\t{resp["error"]["message"]}\n' 
            )
            exit(1)


def b64(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return url_id


def flagged(input, _type):
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_APIKEY")}
    if _type == "file":
        req = requests.get(FILE_BASE + input, headers=headers)
        value = "category"
    elif _type == "hash":
        req = requests.get(FILE_BASE + input, headers=headers)
        value = "category"
    elif _type == "url":
        req = requests.get(URLS_BASE + b64(input), headers=headers)
        value = "result"
    check_api_err(req.json())
    analysis_rslt = req.json()["data"]["attributes"]["last_analysis_results"]
    total = 0
    positive = 0
    for AV in analysis_rslt.keys():
        if analysis_rslt[AV][value] not in [
            "clean",
            "unrated",
            "harmless",
            "undetected",
            "type-unsupported",
            "timeout",
            "harmless",
        ]:
            positive += 1
        total += 1
    if positive:
        return [positive, total]
    else:
        return [None, None]


def comments(input, _type):
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_APIKEY")}
    if _type == "file":
        req = requests.get(FILE_BASE + input + "/comments?limit=30", headers=headers)
    elif _type == "hash":
        req = requests.get(FILE_BASE + input + "/comments?limit=30", headers=headers)
    elif _type == "url":
        req = requests.get(URLS_BASE + b64(input) + "/comments?limit=30", headers=headers)
    check_api_err(req.json())
    comments = list()
    raw_comments = req.json()["data"]
    for comment in raw_comments:
        comment = (
            comment["attributes"]["text"][:99].replace("\t", "").replace("\n", " ")
        )
        comments.append(comment)
    if comments:
        return comments, len(comments)
    else:
        return False


def votes(input, _type):
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_APIKEY")}
    if _type == "file":
        req = requests.get(FILE_BASE + input + "/votes", headers=headers)
    elif _type == "hash":
        req = requests.get(FILE_BASE + input + "/votes", headers=headers)
    elif _type == "url":
        req = requests.get(URLS_BASE + b64(input) + "/votes", headers=headers)
    check_api_err(req.json())
    raw_votes = req.json()["data"]
    if raw_votes:
        verdict = raw_votes[0]["attributes"]["verdict"]
        votes = raw_votes[0]["attributes"]["value"]
        return verdict, votes
    else:
        return False
