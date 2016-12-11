#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2016 Florian Maury
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import os
import io
import json
import flask
import ipaddress
import time
import hashlib
import sqlite3
import http.client
import ssl
import collections
import struct
import base64
import email.utils
import threading
import concurrent.futures

import werkzeug.contrib.cache

import cryptography
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.backends
import cryptography.x509
import cryptography.hazmat.primitives.serialization

# The Flask application per se ; used to bind to addr/port and serve requests
app = flask.Flask(__name__)

# You might want to uncomment the following line if you are using this behing a TLS reverse proxy
# app.config.update({
# 	'PREFERRED_URL_SCHEME': 'https'
# })



# The cache is a simple in-memory cache used to pass around some values initially loaded from disk and cache some
# information retrieved from the web
cache = werkzeug.contrib.cache.SimpleCache()
# dbconn is a SQLite connection to store data about the certification chains received by the /submit endpoint
dbconn = None

# throttling_locks are used to lock the token buckets for non-atomic operations; the throttling_global_lock is used
# to initialize the throttling_global_locks
throttling_global_lock = threading.Lock()
throttling_locks = {}
throttling_delay = 20 * 60  # seconds; New query OK every 20 minutes or so
initial_bucket_token_count = 24 * 3  # Enough for 1 query every 20 minutes per day

# A simple couple of namedtuple that mostly emulates a Rust Result :)
AddChainReturnValue = collections.namedtuple('AddChainReturnValue', ['log', 'sct'])
AddChainError = collections.namedtuple('AddChainError', ['log', 'error', 'sct'])

# log_root_cache_locks contains a dict of locks, indexed by the log URL. This lock is used to update the cache of
# accepted roots and prevent multiple racy in-flight queries
log_root_cache_locks = {}
get_valid_roots_global_lock = threading.Lock()

# Contains the list of log keys, indexed by the log url
global_log_keys = {}

def get_certs(fd):
    """ get_certs reads a file object (readline calls) and "parses" it to discover PEM-encoded certs that are returned
    as python "cryptography"-lib object

    :param fd: an object with "readline()" endpoint (typically a file object or a StringIO
    :return: returns a list of X.509 cryptography-lib object
    """
    cert_lst = []
    acc = ''
    in_cert = False
    s = fd.readline()
    while s != '':
        if s.find('BEGIN CERTIFICATE') != -1:
            if in_cert:
                raise Exception('Malformed chain')
            in_cert = True
            acc += s
        elif s.find('END CERTIFICATE') != -1:
            acc += s
            crypto_cert = cryptography.x509.load_pem_x509_certificate(
                bytes(acc, 'UTF-8'), cryptography.hazmat.backends.default_backend()
            )
            cert_lst.append(crypto_cert)
            acc = ''
            in_cert = False
        elif in_cert:
            acc += s
        s = fd.readline()
    return cert_lst


def build_https_connection(log):
    """ build_https_connection does what the name implies :)

    :param log: the log URL as listed in a log_list.json file (e.g. ct.googleapis.com/rocketeer)
    :return: A http.client.HTTPSConnection object appropriately initialized
    """
    log_dnsname = log.split('/')[0]

    sslctx = ssl.create_default_context()
    sslctx.set_ciphers(
        'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSAAES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:'
        'ECDHE-RSAAES128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:'
        'ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-AES256-GCM-SHA384:'
        'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:'
        'AES256-SHA256:AES128-SHA256:CAMELLIA128-SHA256')
    return http.client.HTTPSConnection(log_dnsname, timeout=30, context=sslctx)


def push_certs(log, certs):
    """ push_certs sends a certificate chain to a log add-chain endpoint

    :param log: the URL of log to which the certificate chain will be pushed (e.g. ct.googleapis.com/rocketeer)
    :param certs: a chain of X.509 certificates as cryptography-lib objects
    :return: a python object representing the answer from the log
    """
    c = build_https_connection(log)

    encoded_certs = {
        'chain': [
            base64.b64encode(
                cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)
            ).decode('UTF-8')
            for cert in certs
        ]
    }

    c.request(
        'POST',
        'https://{}/ct/v1/add-chain'.format(log.rstrip('/')),
        body=json.dumps(encoded_certs),
        headers={
            'Content-Type': 'application/json'
        }
    )
    response = c.getresponse()
    data = response.read()

    if response.status != 200:
        raise Exception('Could not get an answer from the log')

    c.close()
    return json.loads(data.decode('UTF-8'))


def build_bin_sct(sct):
    """ build_bin_sct builds the binary structure of a SCT from a Python dict

    :param sct: a Python dict containing the info from the JSON-decoding of the JSON object returned by a log on a
    add-chain call
    :return: the bytestring representing the binary-encoded SCT
    """
    if sct['sct_version'] != 0:  # v1
        raise Exception('Unsupported SCT version: {}'.format(sct['sct_version']))

    log_id = base64.b64decode(sct['id'])
    if len(log_id) != 32:
        raise Exception('Invalid SCT Log ID: {}'.format(log_id))

    exts = base64.b64decode(sct['extensions'])

    s = struct.pack(
        '>B32sQH',
        sct['sct_version'],
        log_id,
        sct['timestamp'],
        len(exts)
    )
    s += exts
    s += base64.b64decode(sct['signature'])
    return s


def get_verifier(sig, pk):
    """ get_verifier returns a cryptography-lib verifier for a given public key and a CT-signature object
    Currently, RSA/ECDSA and SHA-256 are hard-coded. If other algorithms are ever used, this function will need some
    rewriting.

    :param sig: the CT-signature (encoding the signature data and the algorithms)
    :param pk: the public key that can suppposedly verify the signature, as a cryptography-lib object
    :return: a cryptography-lib verifier
    """

    # Check sig format (hash_type, sig_type, len, signature)
    bin_sig_obj = base64.b64decode(bytes(sig, 'UTF-8'))
    hash_algo, sig_algo, sig_len = struct.unpack('>BBH', bin_sig_obj[:4])
    bin_sig = bin_sig_obj[4:]

    # Check algo and length
    # "3" and "4" identifiers come from
    # https://github.com/google/certificate-transparency/blob/master/python/ct/proto/client.proto
    # DigitallySigned message
    if hash_algo != 4 or (sig_algo != 3 and sig_algo != 1) or sig_len != len(bin_sig):
        raise Exception('Invalid signature format or not yet implemented algorithm')

    # Create verifier
    if sig_algo == 1:
        # RSA
        return pk.verifier(
            bin_sig,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA256()
        )
    elif sig_algo == 3:
        # ECDSA
        return pk.verifier(
            bin_sig,
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                cryptography.hazmat.primitives.hashes.SHA256()
            )
        )
    raise Exception('Never reached')


def build_tbs_sct(sct, cert):
    """ build_tbs_sct builds and returns the bytestring representation of the SCT structure that is "digitally-signed"

    :param sct: a python dict generated by JSON-decoding the information returned by a add-chain call to a log
    :param cert: the end-entity certificate that the SCT corresponds to
    :return: the bytestring representing the SCT structure that is "digitally-signed"
    """
    bin_cert = cert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)
    bin_cert_len = len(bin_cert)
    exts = base64.b64decode(sct['extensions'])

    s = struct.pack(
        '>BBQHBH',
        sct['sct_version'],
        0,  # Signature type = certificate_timestamp
        sct['timestamp'],
        0,  # x509_entry,
        (bin_cert_len >> 16) & 0xFF,
        bin_cert_len & 0xFFFF,
    )
    s += bin_cert
    s += struct.pack(
        '>H', len(exts)
    )
    s += exts
    return s


def validate_sct(cert, sct, pk):
    """ validate_sct does what the name implies

    :param cert: the end-entity certificate tied to the SCT to verify
    :param sct: the SCT information as a JSON-decoded object
    :param pk: the public key of the log that signed the SCT, as a cryptography-lib object
    :return: True on success
    :raise: InvalidSignature if the SCT does not check!
    """
    verifier = get_verifier(sct['signature'], pk)
    tbs_sct = build_tbs_sct(sct, cert)
    verifier.update(tbs_sct)
    return verifier.verify()


def get_log_public_key(key):
    """ Parses a DER-encoded public_key and returns it as a cryptography-lib object

    :param key: a DER-encoded public key
    :return: the corresponding cryptography-lib object
    """
    pk = cryptography.hazmat.primitives.serialization.load_der_public_key(
        base64.b64decode(bytes(key, 'UTF-8')),
        cryptography.hazmat.backends.default_backend()
    )
    return pk


def verify_cert_signature(parent_cert, child_cert):
    """verify_cert_signature verifies that a certificate is signed by the private key associated to a parent cert

    :param parent_cert: the parent cert whose public key is used to verify the child signature
    :param child_cert: the child certificate to verify
    :return: True on success
    :raise: InvalidSignature if the signature is invalid, or Exception if RSA is not used
    TODO add some crypto-agility if need be
    """
    pk = parent_cert.public_key()
    if isinstance(pk, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        verifier = pk.verifier(
            child_cert.signature,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            child_cert.signature_hash_algorithm
        )
        verifier.update(child_cert.tbs_certificate_bytes)
        return verifier.verify()
    raise Exception('Unhandled cryptography pritimive')


def check_certs(certs):
    """ check_certs validates that the cert list provided as argument is a valid cert chain

    :param certs: a list of cryptography-lib X.509 certificate objects
    :return: None
    :raise: Invalid signature if a validation fails or Exception if an unhandled signature algorithm is used
    """
    print('Checking certificate chain consistency')

    child = None
    for parent in certs:
        if not isinstance(child, type(None)):
            verify_cert_signature(parent, child)
        child = parent

def compute_cache_duration(cache_control_hdr, expires_hdr):
    """ compute_cache_duration extracts from various HTTP headers the duration of cache, in seconds. If the duration
    is less than 60 seconds (or no caching instruction is provided by the server), the duration is override to 60 secs.

    :param cache_control_hdr: the "Cache-Control" HTTP header value
    :param expires_hdr: the "Expires" HTTP header value
    :return: a cache duration, in seconds
    """
    duration = 0
    if not isinstance(cache_control_hdr, type(None)):
        for attr in [attr.strip() for attr in cache_control_hdr.split(';')]:
            if attr.lower().find('no-cache') != -1:
                duration = 0
                break
            elif attr.lower().startswith('max-age='):
                try:
                    duration = int(attr[len('max-age='):])
                except ValueError:
                    duration = 0
                break
    elif not isinstance(expires_hdr, type(None)):
        date = email.utils.parsedate(expires_hdr)
        duration = int(time.mktime(date)) - int(time.time())

    duration = max(duration, 60)
    return duration


def get_valid_roots(log):
    """ get_valid_roots retrieves the list of root certificates that are accepted by a log

    :param log: the log URL as listed in log_list.json (e.g. ct.googleapis.com/rocketeer)
    :return:
    """
    # TODO verify that it works appropriately, if the two following lines are commented!
    # global log_root_cache_locks
    # global get_valid_roots_global_lock

    if log not in log_root_cache_locks:
        get_valid_roots_global_lock.acquire()
        if log not in log_root_cache_locks:
            log_root_cache_locks[log] = threading.Lock()
        get_valid_roots_global_lock.release()

    root_cache_key = 'root_cache_{}'.format(log)

    log_root_cache_locks[log].acquire()
    root_cache = cache.get(root_cache_key)
    if isinstance(root_cache, type(None)):
        c = build_https_connection(log)
        c.request('GET', 'https://{}/ct/v1/get-roots'.format(log.rstrip('/')))
        response = c.getresponse()

        data = response.read()
        if response.status != 200:
            raise Exception('Unable to get list of accepted roots from this log')

        cache_control_hdr = response.getheader('Cache-Control')
        expires_hdr = response.getheader('Expires')
        c.close()

        duration = compute_cache_duration(cache_control_hdr, expires_hdr)

        ret_value = json.loads(data.decode('UTF-8'))['certificates']
        cache.set(root_cache_key, ret_value, duration)
    else:
        ret_value = root_cache

    log_root_cache_locks[log].release()
    return ret_value


def check_accepted_root(cert, valid_roots):
    """ check_accepted_root verifies that the provided certs is signed by one of the "valid_roots".
    It does not matter that certs is one of the valid roots. It will check because that root is probably a self-signed
    certificate. This will break if a log accepts a root that is not a self-signed certificate (the "root" is actually
    an intermediate CA)

    :param cert: a cryptography-lib X.509 certificate object that should be signed by one of the "valid_roots"
    :param valid_roots: a list of cryptography-lib X.509 certificate objects that should be signing the "cert"
    :return: True on success
    :raise: InvalidSignature if the signature does not check or Exception if the public key is not a RSA key or if no
    root checks.
    """
    for root in valid_roots:
        bin_root = base64.b64decode(root)
        crypto_root = cryptography.x509.load_der_x509_certificate(
            bin_root,
            cryptography.hazmat.backends.default_backend()
        )
        if cert.issuer == crypto_root.subject:
            pk = crypto_root.public_key()
            if isinstance(pk, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
                verifier = pk.verifier(
                    cert.signature,
                    cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                verifier.update(cert.tbs_certificate_bytes)
                return verifier.verify()
            raise Exception('Unhandled cryptographic primitive')
    raise Exception('No valid root for this certificate chain. This log does not support this cert root.')


def check_perms(chain_file, log_list_file):
    """ check_perms verify that this script as read permission on the necessary files

    :param chain_file: the chain file containing the certificate chain to submit to a log
    :param log_list_file: the log_list.json file from www.certificate-transparency.org
    :return: True if everything checks, or else False
    """
    return (
        os.access(chain_file, os.R_OK)
        and os.access(log_list_file, os.R_OK)
    )


def add_chain(certs, log, log_key):
    """ add_chain orchestrates the insertion of a certificate chain into a log and verifies beforehand and after
    insertion that everything checks

    :param certs: a certificate chain as a list of cryptography-lib X.509 certificate objects
    :param log: the log URL (e.g. ct.googleapis.com/rocketeer)
    :param log_key: the public key of the log
    :return: AddChainReturnValue instance on success or AddChaineError if something failed
    """
    print('Trying log {}'.format(log))
    reason = 'General Error'
    bin_sct = None
    try:
        try:
            print('Fetching list of accepted trust anchors for {}'.format(log))
            valid_roots = get_valid_roots(log)
        except:
            reason = 'cannot get the list of valid trust anchors'
            raise

        try:
            print('Checking accepted trust anchors for {}'.format(log))
            check_accepted_root(certs[-1], valid_roots)
        except:
            reason = 'the chain to submit is not accepted by this log'
            raise

        try:
            print('Pushing the certificate chain to the log for {}'.format(log))
            sct = push_certs(log, certs)
        except:
            reason = 'cannot push the chain to the log'
            raise

        try:
            bin_sct = build_bin_sct(sct)
            log_pk = get_log_public_key(log_key)

            print('Validating SCT validity for {}'.format(log))
            validate_sct(certs[0], sct, log_pk)
        except:
            reason = 'the returned SCT is invalid'
            raise

        return AddChainReturnValue(log, base64.b64encode(bin_sct).decode('UTF-8'))
    except:
        print('Skipping log {}: {}'.format(log, reason))
        return AddChainError(log, reason, bin_sct)


def handle_certs(certs, log_keys):
    """ handle_certs submits a certificate chain to all logs for which we have a public key!

    :param certs: a certificate chain as a list of cryptography-lib X.509 objects
    :param log_keys: a dictionary whose keys the URL of the logs and the values are the log public keys
    :return: returns a python dictionary of dictionaries. The inner dictionaries contain either a valid SCT or else an
    error and optionally an invalid SCT.
    """
    check_certs(certs)

    scts = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as tpe:
        future_to_url = [
            tpe.submit(add_chain, certs, log, log_keys[log])
            for log in log_keys.keys()
        ]

        for future in concurrent.futures.as_completed(future_to_url):
            try:
                ret = future.result()
                if isinstance(ret, AddChainReturnValue):
                    scts[ret.log] = {'sct': ret.sct, 'valid': True}
                else:
                    scts[ret.log] = {'error': ret.error, 'sct': ret.sct, 'valid': False}
            except Exception as e:
                pass

    return scts


def get_log_list(log_list_file):
    """ get_log_list builds and returns a dictionary whose keys are log URLs and values are these log public keys

    :param log_list_file: a log_list.json (as downloaded from www.certificate-transparency.org) filesystem path
    :return: a python dictionary whose keys are log URLs and values are these log public keys
    """
    with open(log_list_file, 'r') as fd:
        data = json.load(fd)

    # The blacklisted_logs are logs that are no longer operated or that are read-only.
    blacklisted_logs = ['log.certly.io', 'ct.izenpe.com', 'ct.googleapis.com/aviator']
    return {
        log['url']: log['key']
        for log in data['logs']
        if log['url'] not in blacklisted_logs
    }


def throttle_submit():
    """ throttle_submit is a very personal and hopefully not-so-wrong implementation of the leaky/token bucket algorithm
    If the throttling delay is 0, then throttling is disabled
    :return: True if access granted, or else False
    :raise: Exception if something really strange is provided as remote_addr
    """
    if throttling_delay <= 0:
        return True

    now = int(time.time())

    # Get a string representation of the enclosing prefix with the largest prefix_len that can be generally announced
    # over the Internet (/24 for IPv4 and /48 for IPv6)
    if flask.request.headers.getlist("X-Real-IP"):
        remote_addr = flask.request.headers.getlist("X-Real-IP")[0]
    else:
        remote_addr = flask.request.remote_addr
    if remote_addr.find('.') != -1:  # IPv4
        network = ipaddress.ip_network('{}/24'.format(remote_addr), strict=False)
    elif remote_addr.find(':') != -1:  # IPv6
        network = ipaddress.ip_network('{}/48'.format(remote_addr), strict=False)
    else:  # Unknown address type or format
        raise Exception('Never reached')

    network_addr = network.network_address.exploded

    # Creates a lock for this network prefix if not already present (double-check locking design pattern)
    if network_addr not in throttling_locks:
        throttling_global_lock.acquire()
        if network_addr not in throttling_locks:
            throttling_locks[network_addr] = threading.Lock()
        throttling_global_lock.release()

    got_a_token = False

    # If this is the very first query that we have from this prefix, we cache that the last query date was "now"
    throttling_cache_last_query_key = 'throttling_cache_last_query_{}'.format(network_addr)
    throttling_cache_last_query = cache.get(throttling_cache_last_query_key)
    if isinstance(throttling_cache_last_query, type(None)):
        cache.set(throttling_cache_last_query_key, now)
        throttling_cache_last_query = now

    # We try to read the current number of tokens
    throttling_cache_key = 'throttling_cache_{}'.format(network_addr)
    throttling_cache = cache.get(throttling_cache_key)
    if isinstance(throttling_cache, type(None)):
        # Sooo, no token exists because this is the very first query; we put the maximum number of token minus the one
        # we get
        throttling_locks[network_addr].acquire()
        if isinstance(throttling_cache, type(None)):
            throttling_cache = initial_bucket_token_count - 1
            cache.set(throttling_cache_key, throttling_cache)
            got_a_token = True
        throttling_locks[network_addr].release()

    # If we don't have a token already, we try to see if we can get one.
    # We loop because the first throttling_cache access was not thread-safe and upon first iteration, we might think
    # there are tokens left (positive throttling_cache value) but the bucket was depleted before we could actually get
    # one! Since this implementation is refilling the bucket in a lazy way (only refill/lock it when it is depleted), we
    # need to loop to grant access to people that are in this case
    attempt = 0
    while not got_a_token and attempt < 2:
        if throttling_cache <= 0 and now - throttling_cache_last_query > throttling_delay:
            throttling_locks[network_addr].acquire()
            if throttling_cache <= 0 and now - throttling_cache_last_query > throttling_delay:
                cache.set(throttling_cache_last_query_key, now)
                token_incr = min(
                    initial_bucket_token_count - throttling_cache,
                    (now - throttling_cache_last_query) // throttling_delay
                )
                cache.set(throttling_cache_key, token_incr)
                throttling_cache = token_incr
            else:
                throttling_cache = cache.get(throttling_cache_key)
            throttling_locks[network_addr].release()

        if throttling_cache > 0:
            # the cache.dec operation is supposed to be "almost thread-safe", according to library documentation.
            # We accept the risk of approximations here
            throttling_cache = cache.dec(throttling_cache_key)
            if throttling_cache >= 0:
                got_a_token = True
            else:
                attempt += 1
                continue
        else:
            # We break because there were no token left when we entered the loop and there are still none, even after a
            # refill attempt; no need to loop once more and find the same result
            break

    return got_a_token


def get_cached_scts(hex_ee_hash):
    """ get_cached_scts returns previously fetched valid SCT from this certificate. The key to perform this search is
    the hex-encoded hash of the end-entity certificate

    :param hex_ee_hash: the hex-encoded hash of the end-entity certificate
    :return: a dictionary of SCTs where the keys are the log URL
    """
    c = dbconn.cursor()
    c.execute('''
        SELECT logs.log, scts.sct
            FROM certs
                INNER JOIN scts
                    ON certs.id = scts.cert_id
                INNER JOIN logs
                    ON scts.log_id = logs.id
            WHERE certs.ee_hash = ?
                AND scts.valid = 1
    ''', (hex_ee_hash,))

    return {
        log: {'sct': sct, 'valid': True}
        for (log, sct) in c.fetchall()
    }


def cache_scts(hex_ee_hash, pem_encoded_cert, scts):
    """ cache_scts performs the converse operation of get_cached_scts; it store in database the SCTs that we received.
    All SCTs are stored, even those that we deemed invalid, for further investigation (might be an unsupported
    signature algorithm?)

    :param hex_ee_hash: the hex-encoded hash of the end-entity certificate
    :param pem_encoded_cert: the PEM-encoded certificate (which will be stored too)
    :param scts: the SCTs as a python dictionary, as returned by get_cached_scts or handle_certs
    :return:
    """
    c = dbconn.cursor()
    c.execute('''
        SELECT id
            FROM certs
            WHERE ee_hash = ?
    ''', (hex_ee_hash,))
    result = c.fetchone()
    if isinstance(result, type(None)):
        c.execute('''
            INSERT INTO certs (ee_hash, cert) VALUES (?, ?);
        ''', (hex_ee_hash, pem_encoded_cert))
        dbconn.commit()
        cert_id = c.lastrowid
    else:
        cert_id = result[0]

    now = int(time.time())
    for log in [log for log in scts.keys() if 'sct' in scts[log] and not isinstance(scts[log]['sct'], type(None))]:
        c.execute('''
            SELECT id
                FROM logs
                WHERE log = ?
        ''', (log,))
        result = c.fetchone()
        log_id = result[0]
        sct = scts[log]['sct']
        valid = scts[log]['valid']
        c.execute('''
            INSERT INTO scts (cert_id, log_id, sct, valid, time) VALUES (?, ?, ?, ?, ?);
        ''', (cert_id, log_id, sct, valid, now))
    dbconn.commit()


def submit_certs(certs):
    """ submit_certs handles a new certificate chain, get the cached SCTs for it, and get new SCTs, cache them and
    ultimately returns both cached SCTs and new ones

    :param certs: the certificate chain as a list of cryptography-lib X.509 certificate objects
    :return: a JSON response to be sent to the HTTP client
    """
    ee_crt = certs[0]
    ee_hash = hashlib.sha256()
    ee_hash.update(ee_crt.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER))
    hex_ee_hash = bytes(ee_hash.hexdigest(), 'UTF-8')
    pem_encoded_cert = ee_crt.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM)

    cached_scts = get_cached_scts(hex_ee_hash)
    log_to_query = set(global_log_keys.keys()).difference(set(cached_scts.keys()))
    log_keys = {log: key for (log, key) in global_log_keys.items() if log in log_to_query}

    scts = handle_certs(certs, log_keys)
    cache_scts(hex_ee_hash, pem_encoded_cert, scts)
    scts.update(cached_scts)

    json_response = json.dumps({
        'scts': scts
    })

    return json_response


@app.route('/submit', methods=['POST'])
def submit_handler():
    try:
        authorized = throttle_submit()
    except:
        flask.abort(400)
        raise Exception('Never reached')
    if not authorized:
        flask.abort(403)
        raise Exception('Never reached')

    if 'cert' in flask.request.form and len(flask.request.form['cert']) != 0:
        # This is the handler that is used if you use the webform. The file field is converted as a string by Javascript
        fd = io.StringIO(flask.request.form['cert'])
    elif 'cert_file' in flask.request.files:
        # This is the handler that is used if you use another HTTP client (curl...)
        fd = flask.request.files['cert_file']
        byte_array = fd.read()
        fd = io.StringIO(byte_array.decode('UTF-8'))
    else:
        flask.abort(400)
        raise Exception('Never reached')

    certs = get_certs(fd)
    fd.close()

    if len(certs) == 0:
        flask.abort(400)
        raise Exception('Never reached')

    json_response = submit_certs(certs)

    response = flask.make_response(json_response)
    response.headers['Content-Type'] = 'application/javascript'
    return response


@app.route('/')
def homepage():
    return flask.render_template(
        'index.html',
        throttling_delay=throttling_delay,
        initial_bucket_token_count=initial_bucket_token_count
    )


def init_app(log_list_file, db_file, cli_throttling_delay, cli_initial_bucket_token_count):
    global dbconn
    global initial_bucket_token_count
    global throttling_delay
    global global_log_keys

    initial_bucket_token_count = cli_initial_bucket_token_count
    throttling_delay = cli_throttling_delay

    global_log_keys = get_log_list(log_list_file)

    db_initialized = os.path.exists(db_file)
    dbconn = sqlite3.connect(db_file)
    c = dbconn.cursor()
    c.execute('''PRAGMA foreign_keys = ON;''')
    if not db_initialized:
        c.execute('''
            CREATE TABLE certs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ee_hash CHAR(32) UNIQUE,
                cert TEXT
            );
            ''')
        c.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log VARCHAR(255) UNIQUE
            );
        ''')
        c.execute('''
            CREATE TABLE scts (
                log_id INTEGER,
                cert_id INTEGER,
                sct TEXT,
                valid BOOLEAN,
                time INTEGER,
                FOREIGN KEY(log_id) REFERENCES logs(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
                FOREIGN KEY(cert_id) REFERENCES certs(id) ON DELETE RESTRICT ON UPDATE RESTRICT
            );
        ''')

    # Add new logs
    for log in global_log_keys.keys():
        try:
            c.execute('''
                INSERT INTO logs (log) VALUES (?);
            ''', (log,))
        except sqlite3.IntegrityError:
            # This log is already in the database
            pass
    dbconn.commit()


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--log-list', dest='log_list_file', required=True,
        help='log_list.json file from the certificate-transparency.org'
    )
    parser.add_argument(
        '-db', '--database', dest='db_file', required=True,
        help='Database file in which the SCTs are stored'
    )
    parser.add_argument(
        '-H', '--host', dest='host', default='127.0.0.1',
        help='IP address to which the webservice will bind'
    )
    parser.add_argument(
        '-p', '--port', dest='port', default=5000,
        help='Port to which the webservice will bind'
    )
    parser.add_argument(
        '-t', '--throttle', dest='throttle', type=int, default=throttling_delay,
        help='Number of seconds after which the throttling algorithm allows a new query in (0 = disabled)'
    )
    parser.add_argument(
        '-b', '--bucket', dest='bucket', type=int, default=initial_bucket_token_count,
        help='Maximum number of queries allowed by the throttling algorithm before depletion'
    )
    args = parser.parse_args()

    init_app(args.log_list_file, args.db_file, args.throttle, args.bucket)

    app.run(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
