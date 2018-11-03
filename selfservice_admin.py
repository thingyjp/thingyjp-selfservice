#!/usr/bin/env python3

import argparse
import common
from easyrsa import Pki, PkiExistsException
import environment
import os

ACTION_INIT = "init"

devicepki = Pki(environment.pkipath_device)
serverpki = Pki(environment.pkipath_server)

pkimapping = {common.MODE_SERVER: serverpki,
              common.MODE_DEVICE: devicepki}

parser = argparse.ArgumentParser(description='thingy.jp self-service admin')
parser.add_argument('--mode', type=str, choices=[common.MODE_SERVER, common.MODE_DEVICE], required=True)
parser.add_argument('--action', type=str, choices=[ACTION_INIT], required=True)
parser.add_argument('--rootcacert', type=str)
parser.add_argument('--subcacert', type=str)
parser.add_argument('--subcakey', type=str)
parser.add_argument('--intermediatecacerts', type=str, nargs='*')

args = parser.parse_args()


def initsanitycheck():
    if args.rootcacert is None or args.subcacert is None or args.subcakey is None:
        print(
            "The root CA certificate, sub CA certificate and private key must be provided to create a %s signing pki" % args.mode)
        exit(1)

    if not os.path.isfile(args.subcacert):
        print("sub CA cert doesn't exist or isn't a file")
        exit(1)

    if not os.path.isfile(args.subcakey):
        print("sub CA key doesn't existing or isn't a file")
        exit(1)

    if args.intermediatecacerts is None:
        print("No intermediate CA certs were provided. This is probably incorrect.")
    else:
        for i in args.intermediatecacerts:
            if not os.path.isfile(i):
                print("intermediate CA cert %s isn't a file or doesn't exist" % i)
                exit(1)


if args.action == ACTION_INIT:
    initsanitycheck()
    pki = pkimapping.get(args.mode)
    try:
        pki.init()
    except PkiExistsException as e:
        print(str(e))
        exit(1)

    pki.subca_init()
    pki.subca_importkeys(args.rootcacert, args.subcacert, args.subcakey, args.intermediatecacerts)
