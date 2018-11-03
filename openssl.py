import subprocess
import re

# [0-9,a-z]{8}-[0-9,a-z]{4}-[0-9,a-z]{4}-[0-9,a-z]{4}-[0-9,a-z]{12}

MODULUSPATTERN = "(?<=Modulus=)[A-F0-9]*"


class PrivateKeyMismatchException(Exception):
    pass


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


def cert_verifychain(chainpath: str, cert: str):
    print("verifying cert using cert chain %s" % chainpath)
    opensslprocess = subprocess.run(['openssl', 'verify', '-show_chain', '--CAfile', chainpath], input=cert,
                                    encoding='ascii', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("stdout: %s, stderr: %s" % (opensslprocess.stdout, opensslprocess.stderr))
    if opensslprocess.returncode != 0:
        raise Exception()


def cert_verifyprivatekey(cert, privatekey):
    opensslprocess = subprocess.run(['openssl', 'x509', '-noout', '-modulus'], input=cert, encoding='ascii',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("stdout: %s, stderr: %s" % (opensslprocess.stdout, opensslprocess.stderr))
    if opensslprocess.returncode != 0:
        raise Exception()
    certmod = re.search(MODULUSPATTERN, opensslprocess.stdout).group(0)

    opensslprocess = subprocess.run(['openssl', 'rsa', '-noout', '-modulus'], input=privatekey, encoding='ascii',
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("stdout: %s, stderr: %s" % (opensslprocess.stdout, opensslprocess.stderr))
    if opensslprocess.returncode != 0:
        raise Exception()
    keymod = re.search(MODULUSPATTERN, opensslprocess.stdout).group(0)

    if keymod != certmod:
        raise PrivateKeyMismatchException()


def cert_normalise(cert):
    pass


def key_normalise(key):
    pass
