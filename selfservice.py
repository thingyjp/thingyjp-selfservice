import json
from flask import Flask, request
from http import HTTPStatus
import environment
from easyrsa import Pki, EasyRsaException

try:
    with open(environment.homedir + "/selfservice.conf") as f:
        conf = json.load(f)
        if conf.get('modes') is None:
            conf['modes'] = ["device"]
except FileNotFoundError as e:
    print("configuration not found or invalid, using defaults")
    conf = {"modes": ["device"]}

print("effective conf: %s" % (json.dumps(conf)))

devicepki = Pki(environment.pkipath_device)
devicepki.check()

serverpki = Pki(environment.pkipath_server)
serverpki.check()

pkimapping = {'device': devicepki, 'server': serverpki}
certtypemapping = {'device': 'client', 'server': 'server'}

app = Flask(__name__)

jsoncontentheaders = {'ContentType': 'application/json'}

badmethodcontenttyperes = json.dumps({'error': 'bad method or content type'}), \
                          HTTPStatus.BAD_REQUEST, jsoncontentheaders


@app.route('/<target>/commission', methods=['GET', 'POST'])
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
                        {'error': ""}), HTTPStatus.INTERNAL_SERVER_ERROR, jsoncontentheaders
                return json.dumps({'bundle': cert}), HTTPStatus.OK, jsoncontentheaders
        return json.dumps(
            {'error': 'required parameters missing or invalid'}), HTTPStatus.BAD_REQUEST, jsoncontentheaders
    return badmethodcontenttyperes


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return json.dumps({'error': 'no %s ' % path}), \
           HTTPStatus.NOT_FOUND, jsoncontentheaders


if __name__ == "__main__":
    cert = environment.homedir + '/pki_test/issued/localhost.crt'
    key = environment.homedir + '/pki_test/private/localhost.key'
    print("cert %s and key %s will be used" % (cert, key))
    app.run(ssl_context=(cert, key))
