import os
import environment
import subprocess
import openssl
from tempfile import NamedTemporaryFile
import git
import re


class EasyRsaException(Exception):
    pass


class PkiDoesntExistException(EasyRsaException):
    pass


class PkiExistsException(EasyRsaException):
    pass


CERTTYPE_SERVER = 'server'
CERTTYPE_CLIENT = 'client'

ROOTCACERT = 'rootca.crt'
INTERMEDIATES = 'intermediates'

expirymapping = {CERTTYPE_SERVER: 365}


class Pki:

    def __init__(self, pkipath):
        self.pkipath = pkipath
        self.rootcacertpath = '%s/%s' % (self.pkipath, ROOTCACERT)
        self.cacertpath = '%s/ca.crt' % self.pkipath
        self.intermediatesdir = "%s/%s" % (self.pkipath, INTERMEDIATES)

    def __calleasyrsa(self, args):
        easyrsaprocess = subprocess.run(
            [environment.easyrsa, '--pki-dir=%s' % self.pkipath, '--batch'] + args, encoding='ascii',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("stderr %s" % easyrsaprocess.stderr)
        print("stdout %s" % easyrsaprocess.stdout)
        print(easyrsaprocess.returncode)
        if easyrsaprocess.returncode != 0:
            raise EasyRsaException(easyrsaprocess.stderr)
        return easyrsaprocess

    def __createreqname(self, target, cn, visibility=None, service=None):
        if service is not None and visibility is not None:
            return '%s-%s-%s-%s' % (target, visibility, service, cn)
        else:
            return '%s-%s' % (target, cn)

    def __appendintermediates__(self, chain):
        if os.path.isdir(self.intermediatesdir):
            print("Appending intermediates from %s" % self.intermediatesdir)
            for i in os.listdir(self.intermediatesdir):
                path = '%s/%s' % (self.intermediatesdir, i)
                if os.path.isfile(path):
                    print("Appending intermediate %s" % path)
                    certdata = open(path).read()
                    if len(certdata) == 0:
                        raise Exception("read 0 bytes from cert")
                    chain += certdata
        else:
            print("No intermediates found, this is probably wrong!")
        return chain

    def __appendcacert__(self, bundle):
        bundle += open(self.cacertpath).read()
        return bundle

    def __appendrootcacert__(self, chain):
        print("Appending root ca cert %s" % self.rootcacertpath)
        chain += open(self.rootcacertpath).read()
        return chain

    def __buildverificationchain__(self, appendown=True):
        chainfile = NamedTemporaryFile()
        chain = ""
        if appendown:
            chain = self.__appendcacert__(chain)
        chain = self.__appendintermediates__(chain)
        chain = self.__appendrootcacert__(chain)
        chainfile.write(chain.encode("utf-8"))
        chainfile.seek(0)

        return chainfile

    def check(self):
        if not os.path.isdir(self.pkipath):
            raise PkiDoesntExistException("pki %s doesn't exist" % self.pkipath)

    def init(self):
        if not os.path.isdir(self.pkipath):
            self.__calleasyrsa(['init-pki'])
            os.mkdir('%s/issued' % self.pkipath)
            git.init(self.pkipath)
        else:
            raise PkiExistsException("pki %s already exists" % self.pkipath)

    def subca_init(self):
        self.__calleasyrsa(['--req-cn=dummy', 'build-ca', 'nopass', 'subca'])
        git.stamp(self.pkipath, "subca init")

    def subca_importkeys(self, rootcert: str, owncert: str, ownkey: str, intermediates: list):
        keypath = "%s/private/ca.key" % self.pkipath
        os.remove(keypath)
        os.remove("%s/reqs/ca.req" % self.pkipath)

        print("importing %s as root CA cert" % rootcert)
        inroot = open(rootcert).read()
        outroot = open(self.rootcacertpath, 'w+')
        outroot.write(inroot)
        outroot.close()

        print("importing %s as CA cert" % owncert)
        inowncert = open(owncert).read()
        outowncert = open('%s/ca.crt' % self.pkipath, 'w+')
        outowncert.write(inowncert)
        outowncert.close()

        print("importing %s as CA key" % ownkey)
        inownkey = open(ownkey).read()
        outownkey = open(keypath, 'w+')
        outownkey.write(inownkey)
        outownkey.close()

        if intermediates is not None:
            os.mkdir(self.intermediatesdir)
            for i in intermediates:
                certname = os.path.basename(i)
                incert = open(i).read()
                print("adding intermediate cert %s" % certname)
                outcert = open("%s/%s" % (self.intermediatesdir, certname), 'w+')
                outcert.write(incert)
                outcert.close()

        # build a chain out of the intermediate certs and the root ca cert
        # and check the sub ca cert we just pulled in is valid
        verificationchain = self.__buildverificationchain__(appendown=False)
        openssl.cert_verifychain(verificationchain.name, inowncert)
        verificationchain.close()

        git.stamp(self.pkipath, "subca certs and key imported")

    def csr_create(self, target, hostname, visibility=None, service=None):
        reqname = self.__createreqname(target, hostname, visibility, service)

        extraargs = []
        if visibility is not None and service is not None:
            extraargs.append('--dn-mode=org')
            extraargs.append('--req-c=JP')
            extraargs.append('--req-st=Shizuoka')
            extraargs.append('--req-city=Shimizu')
            extraargs.append('--req-org=thingy.jp')
            extraargs.append('--req-email=ca@thingy.jp')
            extraargs.append('--req-ou=%s-%s' % (visibility, service))

        easyrsaprocess = self.__calleasyrsa(extraargs + ['--req-cn=%s' % hostname, 'gen-req',
                                                         reqname, 'nopass'])
        csrfile = open('%s/reqs/%s.req' % (self.pkipath, reqname))
        csrdata = csrfile.read()
        git.stamp(self.pkipath, "csr created: %s" % reqname)
        return csrdata

    def csr_import(self, csr, target, cn, visibility=None, service=None):
        with  NamedTemporaryFile() as csrtmp:
            reqname = self.__createreqname(target, cn, visibility, service)
            csrtmp.write(csr.encode('utf-8'))
            csrtmp.seek(0)
            self.__calleasyrsa(['import-req', csrtmp.name, reqname])
            csrtmp.close()
            git.stamp(self.pkipath, "csr imported: %s" % reqname)

    def csr_sign(self, target, cn, visibility, service, certtype, extraopts=[]):
        reqname = self.__createreqname(target, cn, visibility, service)
        self.__calleasyrsa(extraopts + ['sign-req', certtype, reqname])
        git.stamp(self.pkipath, "cert signed: %s" % cn)
        return open("%s/issued/%s.crt" % (self.pkipath, reqname)).read()

    def csr_import_and_sign(self, csr, target, visibility, service, certtype):
        extraopts = []
        if certtype == "server":
            extraopts.append('--subject-alt-name=DNS:%s.%s.thingy.jp' % (service, visibility))

        expiry = expirymapping.get(certtype)
        if expiry is not None:
            extraopts.append('--days=%d' % expiry)

        cn = openssl.getuuidfromcsr(csr)
        # sign the csr, then append the subca cert and intermediates
        # to create a usable bundle
        self.csr_import(csr, target, cn, visibility, service)
        bundle = self.csr_sign(target, cn, visibility, service, certtype, extraopts)
        bundle = self.__appendcacert__(bundle)
        bundle = self.__appendintermediates__(bundle)

        # do a sanity check on the bundle to make sure it
        # will actually work. At the moment this is not using
        # the cert chain in the bundle itself so it's of limited
        # utility but whatever
        verificationchain = self.__buildverificationchain__()
        openssl.cert_verifychain(verificationchain.name, bundle)
        verificationchain.close()

        return bundle

    def csr_abort(self):
        print("poo")

    def cert_import(self, target, hostname, visibility, service, cert):
        certname = self.__createreqname(target, hostname, visibility, service)
        certpath = '%s/issued/%s.crt' % (self.pkipath, certname)
        certfile = open(certpath, mode='w')
        certfile.write(cert)
        certfile.close()
        git.stamp(self.pkipath, "cert imported: %s" % certname)
        print('cert stored in %s' % certpath)
