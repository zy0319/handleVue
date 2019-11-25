import os
import json
import base64
import requests
from datetime import datetime

# RSA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# DSA
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
# from hashlib import SHA1
from Crypto.Random import random
from Crypto.Util.asn1 import DerSequence

# path_to_private_key_pem_file = './handleVueProject/replpriv.pem'
path_to_private_key_pem_file = './handleVueProject/admpriv.pem'
#admin_id = '300:0.NA/20.500.12357'
#prefix = '20.500.12357/ZSQ1'
#ip = '39.107.238.25'
#ip1='101.132.112.222'

ip = '172.171.1.80'
admin_id = '300:0.NA/20.500.12410'
port = 8080
# prefix = '20.500.12357/ZSQ1'

# ip1='101.132.112.222'
# port = 8080
# def main():
    # update_handle_record(prefix, path_to_private_key_pem_file, admin_id, ip, port)
    # create_handle_record(prefix, path_to_private_key_pem_file, admin_id, ip, port)


def update(prefix):
    update_handle_record(prefix, path_to_private_key_pem_file, admin_id, ip, port)

def delete(prefix,ip,port):
    delete_handle_record(prefix, path_to_private_key_pem_file, admin_id, ip=ip, port=port)

def createh(record, prefix,ip,port):
    current_date = datetime.now()
    current_date_format = unicode(current_date.strftime('%Y-%m-%dT%H:%M:%SZ'))
    records = []
    for i in range(len(record.index)):
        records.append({u'index': record.index[i], u'ttl': 86400, u'type': record.type[i], u'timestamp': current_date_format,
                  u'data': {u'value': record.value[i], u'format': u'string'}})
    records.append({u'index': 100, u'ttl': 86400, u'type': u'HS_ADMIN', u'timestamp': current_date_format,
         u'data': {u'value': {u'index': 200, u'handle': unicode(admin_id), u'permissions': u''},
                   u'format': u'admin'}})
    handle_record = {u'values': records, u'handle': unicode(prefix), u'responseCode': 1}
    create_handle_record(handle_record, prefix, path_to_private_key_pem_file, admin_id, ip=ip, port=port)


def reslove(prefix,ip ,port):
    handle_record = get_handle_record(prefix, ip=ip, port=port)
    return handle_record


def get_email_value(handle):
    for x in range(0, len(handle)):
        item = handle[x]
        if item['index'] == 2:
            return handle[x]
    return None


def get_handle_record(handle, ip, port):
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    # Turn off certificate verification as most handle servers have self-signed certificates
    r = requests.get(url, verify=False)
    if r.status_code == 200:
        handle_record = r.json()
    else:
        handle_record = None
    return handle_record


def update_handle_record(handle, key_file, auth_id, ip, port):
    # Get the handle record
    handle_record = get_handle_record(handle, ip, port)
    print handle_record
    # Do some updates on the handle
    email_value = get_email_value(handle_record['values'])
    if email_value is None:
        # Add new email item
        current_date = datetime.now()
        current_date_format = unicode(current_date.strftime('%Y-%m-%dT%H:%M:%SZ'))
        handle_record['values'].append({u'index': 2, u'ttl': 86400, u'type': u'EMAIL', u'timestamp': current_date_format, u'data': {u'value': u'info@thenbs.com', u'format': u'string'}})
    else:
        email_value['data']['value'] = u'info@theNBS.com'
    print handle_record

    # Update the handle server
    headers = {
        'Content-Type': 'application/json;charset=UTF-8'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    body = json.dumps(handle_record)
    # Send the request expecting a response with a WWW-Authenticate header
    # The server will give us a 401 error and challenged us
    r = requests.put(url, headers=headers, verify=False, data=body)
    # Build the authorisation header that will response to the server challenge
    headers['Authorization'] = create_authorisation_header(r, key_file, auth_id)

    # Send the request again with a valid correctly signed Authorization header
    r2 = requests.put(url, headers=headers, verify=False, data=body)
    print r2.status_code, r2.reason
    return r2


def create_handle_record(handle_record, handle, key_file, auth_id, ip, port):
    headers = {
        'Content-Type': 'application/json;charset=UTF-8'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle
    body = json.dumps(handle_record)

    # Send the request expecting a response with a WWW-Authenticate header
    # The server will give us a 401 error and challenged us
    r = requests.put(url, headers=headers, verify=False, data=body)

    # Build the authorisation header that will response to the server challenge
    headers['Authorization'] = create_authorisation_header(r, key_file, auth_id)

    # Send the request again with a valid correctly signed Authorization header
    r2 = requests.put(url, headers=headers, verify=False, data=body)
    print r2.status_code, r2.reason
    return r2

def delete_handle_record(handle, key_file, auth_id, ip, port):
    headers = {
        'Content-Type': 'application/json;charset=UTF-8'
    }
    url = 'https://' + ip + ':' + str(port) + '/api/handles/' + handle

    # Send the request expecting a response with a WWW-Authenticate header
    # The server will give us a 401 error and challenged us
    r = requests.delete(url, headers=headers, verify=False)

    # Build the authorisation header that will response to the server challenge
    headers['Authorization'] = create_authorisation_header(r, key_file, auth_id)

    # Send the request again with a valid correctly signed Authorization header
    r2 = requests.delete(url, headers=headers, verify=False)
    print r2.status_code, r2.reason

    return r2


def create_authorisation_header(response, key_file, auth_id):
    # Unpick number once (nonce) and session id from server response (this is the challenge)
    # authenticate_header = response.headers['WWW-Authenticate']
    # authenticate_header_dict = parse_authenticate_header(authenticate_header)
    # server_nonce_bytes = base64.b64decode(authenticate_header_dict['nonce'])
    # session_id = authenticate_header_dict['sessionId']
    #
    # # Generate a client number once (cnonce)
    # client_nonce_bytes = generate_client_nonce_bytes()
    # client_nonce_string = base64.b64encode(client_nonce_bytes)
    #
    # # Our response has to be the signature of server nonce + client nonce
    # combined_nonce_bytes = server_nonce_bytes + client_nonce_bytes
    # signature_bytes = sign_bytes_rsa(combined_nonce_bytes, key_file)
    # signature_string = base64.b64encode(signature_bytes)
    #
    # # Build the authorisation header to send with the request
    # authorization_header_string = build_complex_authorization_string(signature_string, 'HS_PUBKEY', 'SHA1',
    #                                                                  session_id, client_nonce_string, auth_id)
    #

    authenticateHeader = response.headers["WWW-Authenticate"]
    authenticateHeaderDict = parseAuthenticateHeader(authenticateHeader)
    serverNonceBytes = base64.b64decode(authenticateHeaderDict["nonce"])
    sessionId = authenticateHeaderDict["sessionId"]
    clientNonceBytes = generateClientNonceBytes()
    clientNonceString = base64.b64encode(clientNonceBytes)
    combinedNonceBytes = serverNonceBytes + clientNonceBytes
    signatureBytes = signBytesSHA256(combinedNonceBytes, key_file)
    signatureString = base64.b64encode(signatureBytes)
    authorizationHeaderString = build_complex_authorization_string(signatureString, "HS_PUBKEY", "SHA256", sessionId,
                                                      clientNonceString, auth_id)
    # headers["Authorization"] = authorizationHeaderString

    return authorizationHeaderString




def parseAuthenticateHeader(authenticateHeader):
    result = {}
    tokens = authenticateHeader.split(", ");
    for token in tokens:
        firstEquals = token.find("=")
        key = token[0:firstEquals]
        # quick and dirty parsing of the expected WWW-Authenticate headers
        if key == "Basic realm":
            continue
        if key == "Handle sessionId":
            key = "sessionId"
        value = token[firstEquals + 2:len(token) - 1]
        result[key] = value
    return result
def generateClientNonceBytes():
    return bytearray(os.urandom(16))

def signBytesSHA256(bytesArray, pathToPrivateKeyPemFile):
    key = open(pathToPrivateKeyPemFile, "r").read()
    rsakey = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(bytesArray)
    sign = signer.sign(digest)
    return sign


def sign_bytes_rsa(byte_array, path_to_private_key_pem_file):
    # Use this method for RSA keys
    key = open(path_to_private_key_pem_file, 'r').read()
    rsa_key = RSA.importKey(key)
    signer = PKCS1_v1_5.new(rsa_key)
    buf = buffer(byte_array)
    digest = SHA256.new(buf)
    digest.update(buffer(byte_array))
    sign = signer.sign(digest)
    return sign


def sign_bytes_dsa(byte_array, path_to_private_key_pem_file):
    # Use this method for DSA keys
    key = open(path_to_private_key_pem_file, 'r').read()
    # Import the key
    dsa_key = DSA.importKey(key)

    # Create a digest of nonce + cnonce
    # This only seems to work with SHA1 (SHA256 gives us a 401 error)
    buf = buffer(byte_array)
    digest = SHA256.new(buf).digest()

    # Digitally sign the digest with our private key
    # The corresponding public key is in our admin handle on the server
    k = random.StrongRandom().randint(1, dsa_key.q-1)
    sign = dsa_key.sign(digest, k)

    # Signature bytes from a DSA key need to be DER-encoded
    # This signature is in two parts (r and s)
    seq = DerSequence()
    seq.append(sign[0])
    seq.append(sign[1])

    return seq.encode()


def build_complex_authorization_string(signature_string, type_string, alg, session_id, client_nonce_string, auth_id):
    result = ('Handle ' +
              'version="0", ' +
              'sessionId="' + session_id + '", '
              'cnonce="' + client_nonce_string + '", '
              'id="' + auth_id + '", '
              'type="' + type_string + '", '
              'alg="' + alg + '", '
              'signature="' + signature_string + '"')
    return result


def parse_authenticate_header(authenticate_header):
    result = {}
    tokens = authenticate_header.split(', ')
    for token in tokens:
        first_equals = token.find('=')
        key = token[0:first_equals]
        # quick and dirty parsing of the expected WWW-Authenticate headers
        if key == 'Basic realm':
            continue

        if key == 'Handle sessionId':
            key = 'sessionId'

        value = token[first_equals + 2: len(token) - 1]
        result[key] = value

    return result

def generate_client_nonce_bytes():
    return bytearray(os.urandom(16))




