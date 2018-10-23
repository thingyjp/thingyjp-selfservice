from os import environ
from os.path import expanduser

homedir = environ.get('THINGYJP_HOME')
if homedir is None:
    homedir = expanduser('~/.thingyjp')

url = environ.get('THINGYJP_SELFSERVICEURL')
if url is None:
    url = "http://selfservice.public.thingy.jp/wtf"

pkipath_user = "%s/pki_user" % homedir
pkipath_server = "%s/pki_server" % homedir
pkipath_device = "%s/pki_device" % homedir
pkipath_test = "%s/pki_test" % homedir
LOGFILE = "%s/log" % homedir

easyrsa = environ.get('EASYRSA')
if easyrsa is None:
    easyrsa = './thingyjp-scripts/easy-rsa/easyrsa3/easyrsa'
