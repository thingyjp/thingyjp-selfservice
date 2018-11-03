#!/usr/bin/env python3

import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import environment
import json
from easyrsa import Pki, PkiExistsException
import uuid
import common

parser = argparse.ArgumentParser(description='thingy.jp self-service client')
parser.add_argument('--mode', type=str, choices=[common.MODE_SERVER, common.MODE_DEVICE], required=True)
parser.add_argument('--action', type=str,
                    choices=[common.ACTION_COMMISSION, common.ACTION_RENEW, common.ACTION_DECOMMISSION], required=True)

parser.add_argument('--fqdn', type=str)
parser.add_argument('--visibility', type=str, choices=['public', 'private'])
parser.add_argument('--service', type=str, choices=[common.SERVICE_MQTT, common.SERVICE_SELFSERVICE])

args = parser.parse_args()

if args.mode == common.MODE_SERVER:
    if args.fqdn is None or args.service is None or args.visibility is None:
        raise Exception("in server mode the fqdn, services and visibility are required")

userpki = Pki(environment.pkipath_user)

try:
    userpki.init()
except PkiExistsException:
    pass

url = "%s/%s/%s" % (environment.url, args.mode, args.action)

requestbody = {}

if args.action == common.ACTION_COMMISSION:
    if args.mode == common.MODE_SERVER:
        hostname = args.fqdn
    elif args.mode == common.MODE_DEVICE:
        hostname = str(uuid.uuid4())
    else:
        raise Exception()

    print("requesting %s cert for %s" % (args.mode, hostname))

    csr = userpki.csr_create(args.mode, hostname, visibility=args.visibility, service=args.service)
    requestbody['csr'] = csr
    if args.visibility is not None:
        requestbody['visibility'] = args.visibility
    if args.service is not None:
        requestbody['service'] = args.service

    req = Request(url, data=json.dumps(requestbody).encode("utf-8"), headers={'Content-type': 'application/json'})

    try:
        print("req: %s" % json.dumps(requestbody))
        res = json.loads(urlopen(req, cafile=environment.rootcert).read())
        print("res: %s" % res)
        userpki.cert_import(args.mode, hostname, args.visibility, args.service, res.get('bundle'))
    except HTTPError as e:
        userpki.csr_abort()
        error = json.loads(e.read())
        print("error: %s" % error.get('error', None))
elif args.action == common.ACTION_RENEW:
    print("not supported yet")
elif args.action == common.ACTION_DECOMMISSION:
    print("not supported yet")
