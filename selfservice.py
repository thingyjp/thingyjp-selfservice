import json
from flask import Flask, request
from http import HTTPStatus
from OpenSSL import crypto

app = Flask(__name__)

jsoncontentheaders = {'ContentType': 'application/json'}


@app.route('/device/commission', methods=['GET', 'POST'])
def device_commission():
    if request.method == 'POST' and request.content_type == "application/json":
        requestjson = request.get_json();
        if requestjson is not None:
            csrdata = requestjson.get('csr', None)
            if csrdata is not None:
                try:
                    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrdata)
                    cert = crypto.x509()
                    return json.dumps({}), HTTPStatus.OK, jsoncontentheaders
                except:
                    return json.dumps({'error': 'unable to parse CSR'}), \
                           HTTPStatus.BAD_REQUEST, jsoncontentheaders
        return json.dumps({'error': 'required parameters missing or invalid'}), \
               HTTPStatus.BAD_REQUEST, jsoncontentheaders
    return json.dumps({'error': 'bad method or content type'}), \
           HTTPStatus.BAD_REQUEST, jsoncontentheaders
