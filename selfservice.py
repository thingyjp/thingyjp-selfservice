import json
import subprocess
from flask import Flask, request
from http import HTTPStatus
from os.path import expanduser

app = Flask(__name__)

jsoncontentheaders = {'ContentType': 'application/json'}


@app.route('/device/commission', methods=['GET', 'POST'])
def device_commission():
    if request.method == 'POST' and request.content_type == "application/json":
        requestjson = request.get_json()
        if requestjson is not None:
            csrdata = requestjson.get('csr', None)
            if csrdata is not None:
                createcertprocess = subprocess.run(
                    ["./device_createcert.sh"], cwd="./thingyjp-scripts", input=csrdata, encoding='ascii',
                    stdout=subprocess.PIPE)
                return json.dumps({'bundle': createcertprocess.stdout}), HTTPStatus.OK, jsoncontentheaders
        return json.dumps({'error': 'required parameters missing or invalid'}), \
               HTTPStatus.BAD_REQUEST, jsoncontentheaders
    return json.dumps({'error': 'bad method or content type'}), \
           HTTPStatus.BAD_REQUEST, jsoncontentheaders


if __name__ == "__main__":
    app.run(ssl_context=(
        expanduser('~/.thingyjp/pki_user/issued/localhost.crt'),
        expanduser('~/.thingyjp/pki_user/private/localhost.key')))
