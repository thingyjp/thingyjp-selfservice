import subprocess
import re


# [0-9,a-z]{8}-[0-9,a-z]{4}-[0-9,a-z]{4}-[0-9,a-z]{4}-[0-9,a-z]{12}

def getuuidfromcsr(csr):
    opensslprocess = subprocess.run(
        ['openssl', 'req', '-noout', '-subject'], input=csr, encoding='ascii',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if opensslprocess.returncode == 0:
        matches = re.search('(?<=CN = )[a-zA-Z0-9\ \-\.]*(?=(,|$))',
                            opensslprocess.stdout)
        if matches is None:
            raise Exception("couldn't find CN")
        uuid = matches.group(0)
        return uuid
