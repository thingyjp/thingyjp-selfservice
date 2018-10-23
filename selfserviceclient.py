#!/usr/bin/env python3

import argparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import environment
import json
from easyrsa import Pki
import uuid

MODE_SERVER = 'server'
MODE_DEVICE = 'device'

ACTION_COMMISSION = 'commission'
ACTION_RENEW = 'renew'
ACTION_DECOMMISSION = 'decommission'

SERVICE_MQTT = 'mqtt'
SERVICE_SELFSERVICE = 'selfservice'

parser = argparse.ArgumentParser(description='thingy.jp self-service client')
parser.add_argument('--mode', type=str, choices=[MODE_SERVER, MODE_DEVICE], required=True)
parser.add_argument('--action', type=str, choices=[ACTION_COMMISSION, ACTION_DECOMMISSION], required=True)

parser.add_argument('--fqdn', type=str)
parser.add_argument('--visibility', type=str, choices=['public', 'private'])
parser.add_argument('--service', type=str, choices=[SERVICE_MQTT, SERVICE_SELFSERVICE])

args = parser.parse_args()

if args.mode == MODE_SERVER:
    if args.fqdn is None or args.service is None or args.visibility is None:
        raise Exception("in server mode the fqdn, services and visibility are required")

userpki = Pki(environment.pkipath_user)
userpki.init()

url = "%s/%s/%s" % (environment.url, args.mode, args.action)

requestbody = {}

if args.action == ACTION_COMMISSION:
    if args.mode == MODE_SERVER:
        cn = args.fqdn
    elif args.mode == MODE_DEVICE:
        cn = str(uuid.uuid4())
    else:
        raise Exception()

    print("requesting %s cert for %s" % (args.mode, cn))

    csr = userpki.csr_create(args.mode, cn, visibility=args.visibility, service=args.service)
    requestbody['csr'] = csr
    if args.visibility is not None:
        requestbody['visibility'] = args.visibility
    if args.service is not None:
        requestbody['service'] = args.service

    req = Request(url, data=json.dumps(requestbody).encode("utf-8"), headers={'Content-type': 'application/json'})

    try:
        print("req: %s" % json.dumps(requestbody))
        res = json.loads(urlopen(req, cafile="%s/%s" % (environment.homedir, 'thingyjp_root.crt')).read())
        print("res: %s" % res)
        userpki.cert_import(args.mode, cn, res.get('bundle'))
    except HTTPError as e:
        userpki.csr_abort()
        error = json.loads(e.read())
        print("error: %s" % error.get('error', None))
elif args.action == ACTION_DECOMMISSION:
    print("not supported yet")
