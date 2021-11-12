import requests
import hashlib
import sys


def convert_psw_sha1(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest()


def get_query_chars(sha1_psw):
    return sha1_psw[:5].upper()


def get_tail_chars(sha1_psw):
    return sha1_psw[5:].upper()


def request_api_data(query_chars):
    url = 'https://api.pwnedpasswords.com/range/' + query_chars
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error: API returned status code {res.status_code}')
    return res


def get_psw_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


def main(args):
    for psw in args:
        sha1_psw = convert_psw_sha1(psw)
        response = request_api_data(get_query_chars(sha1_psw))
        leak_count = get_psw_leak_count(response, get_tail_chars(sha1_psw))
        print(f'{psw} found {leak_count} times!')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
