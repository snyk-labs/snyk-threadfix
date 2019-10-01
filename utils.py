from pathlib import Path
import requests
import json
import os


def get_default_token_path():
    home = str(Path.home())
    default_token_path = "%s/.config/configstore/snyk.json" % home
    return default_token_path


def get_token_from_file(token_file_path):
    path = token_file_path

    try:
        with open(path, "r") as f:
            json_obj = json.load(f)
            token = json_obj["api"]
            return token
    except FileNotFoundError as fnfe:
        print("Snyk auth token not found at %s" % path)
        print("Run `snyk auth` (see https://github.com/snyk/snyk#installation) or manually create this file with your token.")
        raise fnfe
    except KeyError as ke:
        print("Snyk auth token file is not properly formed: %s" % path)
        print("Run `snyk auth` (see https://github.com/snyk/snyk#installation) or manually create this file with your token.")
        raise ke


def get_token_by_env_var():
    return os.environ.get('SNYK_TOKEN')


def get_token():
    t = get_token_by_env_var()
    if not t:
        token_file_path = get_default_token_path()
        t = get_token_from_file(token_file_path)
    return t


def get_snyk_api_headers(snyk_token):
    snyk_api_headers = {
        'Authorization': 'token %s' % snyk_token
    }
    return snyk_api_headers


def validate_token(snyk_token):
    h = get_snyk_api_headers(snyk_token)
    full_api_url = 'https://snyk.io/api/v1/'
    resp = requests.get(full_api_url, headers=h)
    return resp.ok
