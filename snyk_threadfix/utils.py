import json
import os
import sys
from pathlib import Path

import requests


def get_default_token_path():
    home = str(Path.home())
    default_token_path = "%s/.config/configstore/snyk.json" % home
    return default_token_path


def get_token_from_file(token_file_path):
    path = token_file_path

    with open(path, "r") as f:
        json_obj = json.load(f)
        token = json_obj["api"]
        return token


def get_token_by_env_var():
    return os.environ.get("SNYK_TOKEN")


def get_token():
    t = get_token_by_env_var()
    if not t:
        token_file_path = get_default_token_path()
        t = get_token_from_file(token_file_path)
    return t


def get_snyk_api_headers(snyk_token):
    snyk_api_headers = {"Authorization": "token %s" % snyk_token}
    return snyk_api_headers


def validate_token(snyk_token):
    h = get_snyk_api_headers(snyk_token)
    full_api_url = "https://snyk.io/api/v1/"
    resp = requests.get(full_api_url, headers=h)
    return resp.ok
