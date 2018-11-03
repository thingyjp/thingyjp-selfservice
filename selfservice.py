#!/usr/bin/env python3

import json
from flask import Flask, request
from http import HTTPStatus
import environment
import easyrsa
from easyrsa import Pki, EasyRsaException, PkiDoesntExistException
import common
import os

SELFSERVICEDIR = os.path.normpath('%s/selfservice/' % environment.homedir)

try:
    with open("%s/conf.json" % SELFSERVICEDIR) as f:
        conf = json.load(f)
        if conf.get('modes') is None:
            conf['modes'] = ["device"]
except FileNotFoundError as e:
    print("configuration not found or invalid, using defaults")
    conf = {"modes": ["device"]}

print("effective conf: %s" % (json.dumps(conf)))

devicepki = None
if common.MODE_DEVICE in conf['modes']:
    devicepki = Pki(environment.pkipath_device)
    try:
        devicepki.check()
    except PkiDoesntExistException:
        print("Device pki doesn't exist, your configuration is either incorrect or you need to initialise it")
        exit(1)

serverpki = None
if common.MODE_SERVER in conf['modes']:
    serverpki = Pki(environment.pkipath_server)
    try:
        serverpki.check()
    except PkiDoesntExistException:
        print("Server pki doesn't exist, your configuration is either incorrect or you need to initialise it")
        exit(1)

pkimapping = {common.MODE_SERVER: serverpki, common.MODE_DEVICE: devicepki}
certtypemapping = {common.MODE_SERVER: easyrsa.CERTTYPE_SERVER, common.MODE_DEVICE: easyrsa.CERTTYPE_CLIENT}

app = Flask(__name__)

jsoncontentheaders = {'ContentType': 'application/json'}

badmethodcontenttyperes = json.dumps({'error': 'bad method or content type'}), \
                          HTTPStatus.BAD_REQUEST, jsoncontentheaders


@app.route('/<target>/%s' % common.ACTION_COMMISSION, methods=['GET', 'POST'])
def commission(target):
    if request.method == 'POST' and request.content_type == "application/json":
        requestjson = request.get_json()
        if requestjson is not None:
            csrdata = requestjson.get('csr', None)
            if csrdata is not None:
                pki = pkimapping.get(target)
                try:
                    cert = pki.csr_import_and_sign(csrdata, target, requestjson.get('visibility'),
                                                   requestjson.get('service'), certtypemapping.get(target))
                except EasyRsaException as easyrsaexception:
                    return json.dumps(
                        {'error': str(easyrsaexception)}), HTTPStatus.INTERNAL_SERVER_ERROR, jsoncontentheaders
                return json.dumps({'bundle': cert}), HTTPStatus.OK, jsoncontentheaders
        return json.dumps(
            {'error': 'required parameters missing or invalid'}), HTTPStatus.BAD_REQUEST, jsoncontentheaders
    return badmethodcontenttyperes


@app.route('/<target>/%s' % common.ACTION_RENEW, methods=['GET', 'POST'])
def renew(target):
    return badmethodcontenttyperes


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return json.dumps({'error': 'no %s ' % path}), \
           HTTPStatus.NOT_FOUND, jsoncontentheaders


if __name__ == "__main__":
    cert = '%s/localhost.crt' % SELFSERVICEDIR
    key = '%s/localhost.key' % SELFSERVICEDIR
    print("cert %s and key %s will be used" % (cert, key))
    app.run(ssl_context=(cert, key))
