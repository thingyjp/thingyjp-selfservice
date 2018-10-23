import os
import environment
import subprocess
import openssl
from tempfile import NamedTemporaryFile
import git


class EasyRsaException(Exception):
    pass


class CSRExistsException(Exception):
    pass


CERTTYPE_SERVER = 'server'
CERTTYPE_CLIENT = 'client'

expirymapping = {CERTTYPE_SERVER: 365}


class Pki:

    def __init__(self, pkipath):
        self.pkipath = pkipath

    def __calleasyrsa(self, args):
        easyrsaprocess = subprocess.run(
            [environment.easyrsa, '--pki-dir=%s' % self.pkipath, '--batch'] + args, encoding='ascii',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(easyrsaprocess.stderr)
        print(easyrsaprocess.stdout)
        print(easyrsaprocess.returncode)
        if easyrsaprocess.returncode != 0:
            raise EasyRsaException()
        return easyrsaprocess

    def __createreqname(self, target, cn, visibility=None, service=None):
        if service is not None and visibility is not None:
            return '%s-%s-%s-%s' % (target, visibility, service, cn)
        else:
            return '%s-%s' % (target, cn)

    def check(self):
        if not os.path.isdir(self.pkipath):
            raise Exception("pki %s doesn't exist" % self.pkipath)

    def init(self):
        if not os.path.isdir(self.pkipath):
            self.__calleasyrsa(['init-pki'])
            os.mkdir('%s/issued' % self.pkipath)
            git.init(self.pkipath)

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
            easyrsaprocess = self.__calleasyrsa(['import-req', csrtmp.name, reqname])
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
        self.csr_import(csr, target, cn, visibility, service)
        bundle = self.csr_sign(target, cn, visibility, service, certtype, extraopts)
        intermediatesdir = "%s/intermediates" % self.pkipath
        if os.path.isdir(intermediatesdir):
            for e in os.listdir(intermediatesdir):
                if os.path.isfile(e):
                    bundle += open(e).read()
        cacert = "%s/ca.crt" % self.pkipath
        bundle += open(cacert).read()
        return bundle

    def csr_abort(self):
        print("poo")

    def cert_import(self, prefix, cn, cert):
        certname = '%s-%s' % (prefix, cn)
        certpath = '%s/issued/%s.crt' % (self.pkipath, certname)
        certfile = open(certpath, mode='w')
        certfile.write(cert)
        certfile.close()
        git.stamp(self.pkipath, "cert imported: %s" % certname)
        print('cert stored in %s' % certpath)
