import argparse
import binascii
import json
import os
import re
import socket
import sys
import time
import urllib.parse

import requests
import requests.cookies
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import PBKDF2


class SpeedportApi:
    def __init__(self, url: str, password: str):

        if not url.endswith('/'):
            url += '/'
        self._url = url
        self._password = password

        self._cookies = requests.cookies.RequestsCookieJar()
        self._session = requests.Session()

        self._login_challenge = None
        """
        Challenge for the login
        
        :type login_challenge: bytes
        """

        self._derive_dk = ''

        socket.setdefaulttimeout(7)

    def _get_challenge_val(self):
        """
        Reads the challenge for the login step
        """
        challenge = None
        csrf_token = None
        html = self._open_site('html/login/index.html?lang=de')
        for line in html.splitlines():
            match = re.match(r'\s*var\s+csrf_token\s*=\s*(.+?);\s*', line)
            if match is not None:
                csrf_token = match.group(1).strip('"').strip("'")
            match = re.match(r'\s*var\s+challenge\s*=\s*(.+?);\s*', line)
            if match is not None:
                challenge = match.group(1).strip('"').strip("'")

        if challenge is None:
            raise Exception('Could not fetch challenge')
        if csrf_token is None:
            raise Exception('Could not fetch csrf_token')

        self._login_challenge = challenge
        self.set_cookie("challengev", challenge)

    def login(self):
        """
        Executes a login into the web UI
        """
        self._get_challenge_val()
        # Hash password with challenge_val
        sha256_full = SHA256.new()
        sha256_full.update((self._login_challenge + ':' + self._password).encode('utf-8'))
        encrypted_password = sha256_full.hexdigest()

        # Hash only password
        sha256_passwort = SHA256.new()
        sha256_passwort.update(self._password.encode('utf-8'))
        sha256_loginpwd = sha256_passwort.hexdigest()

        # Get hashed derivedk
        self._derive_dk = binascii.hexlify(PBKDF2(sha256_loginpwd,
                                                  self._login_challenge[:16].encode('utf-8'), 16, 1000)
                                           )

        # Finally login
        json_string = self._open_site('data/Login.json',
                                      {"csrf_token": "nulltoken",
                                       "showpw": 0,
                                       "password": encrypted_password,
                                       'challengev': self._login_challenge})
        json_object = self.string_to_json(json_string)

        # Check valid response
        for x in json_object:
            if x["vartype"] == "status":
                if x["varid"] == "login" and x["varvalue"] != "success":
                    raise Exception("Failed to login")

                if x["varid"] == "status" and x["varvalue"] != "ok":
                    raise Exception("Failed to login")

        # Set needed cookies
        self.set_cookie("derivedk", self._derive_dk.decode('utf-8'))

    def _get_reboot_csrf(self):
        """
        Gets the CSRF token for the problem handling page

        :return: CSRF token
        :rtype: str
        """
        csrf_token = None
        html = self._open_site('html/content/config/problem_handling.html?lang=de', None)
        for line in html.splitlines():
            match = re.match(r'\s*var\s+csrf_token\s*=\s*(.+?);\s*', line)
            if match is not None:
                csrf_token = match.group(1).strip('"').strip("'")

        # Found a crsf token?
        if csrf_token is None:
            raise Exception('Could not fetch csrf_token')

        return csrf_token

    def reboot(self):
        """
        Reboots the device
        """
        csrf_token = self._get_reboot_csrf()

        # Check if valid crsf token found
        if csrf_token == "nulltoken":
            raise Exception("You don't seem to be logged in")

        # Hash reboot command
        aes = AES.new(binascii.unhexlify(self._derive_dk), AES.MODE_CCM,
                      binascii.unhexlify(self._login_challenge[16:32].encode('utf-8')),
                      mac_len=8)
        aes.update(binascii.unhexlify(self._login_challenge[32:48].encode('utf-8')))
        encrypted = aes.encrypt_and_digest("reboot_device=true&csrf_token=" + urllib.parse.quote_plus(csrf_token))

        # Get reboot token
        token = binascii.hexlify(encrypted[0] + encrypted[1])

        # Reboot using token
        json_string = self._open_site('data/Reboot.json', token)
        json_object = self.string_to_json(json_string)

        # Check valid response
        for x in json_object:
            if x["vartype"] == "status" and x["varid"] == "status" and x["varvalue"] != "ok":
                raise Exception("Couldn't reboot - response: " + str(json_object))

    def wait_for_reboot(self):
        """
        Waits until the speedport responds again
        """
        start = time.time()

        while True:
            try:
                self._open_site('data/Reboot.json', None)
                break
            except Exception:
                # Only try for 4 minutes
                if time.time() - start > 240:
                    raise Exception("Speedport still not rebooted after 4 minutes")

    def _open_site(self, url, params=None):
        """
        Opens the given url

        :param url: Relative url
        :param params: Post parameters
        :return: Body
        """
        url = self._url + url

        header = {"Content-type": "application/x-www-form-urlencoded", "charset": "UTF-8"}
        print('Requesting ' + url)
        if params is not None:
            print('With payload: ' + str(params))
            reply = self._session.post(url, data=params, headers=header, timeout=10)
        else:
            reply = self._session.get(url, headers=header, timeout=10)

        print('Cookie response')
        for cookie in self._cookies:
            print(cookie.name + ' -> ' + cookie.value)
        return reply.text

    @staticmethod
    def string_to_json(string):
        """
        Converts a strong to json

        :param string: String
        :return: Json dict
        :rtype: dict
        """
        # Replace special tokens
        string = string.strip().replace("\n", "").replace("\t", "")

        # Some strings are invalid JSON object (Additional comma at the end...)
        if string[-2] == ",":
            string_list = list(string)
            string_list[-2] = ""

            return json.loads("".join(string_list))

        return json.loads(string)

    def set_cookie(self, name, value):
        """
        Sets a cookie

        :param name: Name
        :param value: Value
        """
        self._session.cookies.set(name, value)


def main():
    parser = argparse.ArgumentParser(description='Reboots a speedport hybrid router')
    parser.add_argument('mode', choices=['login', 'reboot'],
                        help='The action that should be executed (a login test or reboot)')
    parser.add_argument('-c', '--config', dest='config', help='Path to the config.json file',
                        default='config.json')

    args = parser.parse_args()
    config_path = args.config
    if not os.path.isfile(config_path):
        raise FileNotFoundError('Config not found: ' + config_path)

    with open(config_path) as file:
        config = json.loads(file.read())

    api = SpeedportApi(config['speedport_url'], config['device_password'])
    if args.mode == 'login':
        print("Testing login...")
        api.login()
        print('Success!')
        return 0
    if args.mode == 'reboot':
        print("Logging in...")
        api.login()

        # Then reboot
        print("Start Rebooting...")
        api.reboot()

        # Then wait until rebooted
        print("Wait until rebooting finished...")
        api.wait_for_reboot()

        # Finished
        print("Rebootet Speedport successfully!")
        return 0


if __name__ == '__main__':
    sys.exit(main())
