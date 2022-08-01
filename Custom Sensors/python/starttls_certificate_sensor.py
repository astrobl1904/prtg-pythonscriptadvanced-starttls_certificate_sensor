# -*- coding: utf-8 -*-
"""
Monitor certificates of services that require STARTTLS and return a JSON formatted sensor result.

This custom Python script sensor is used to monitor certificates of services that require STARTTLS
to initiate a secure transport. It takes the same parameter as the PRTG built-in sensor
`SSL Certificate` but additionally requires the protocol the sensor must use to communicate with
the remote endpoint.
The list of protocols is currently limited to `SMTP`, `LMTP`, and `LDAP`.

The sensor result in JSON contains the same channels as the `SSL Certificate` sensor with channel
`Days to Expiration` set as primary channel.

Keyword for additional parameters:
port                        -- Port for the connection to the target endpoint (default: 25)
protocol                    -- Protocol used with the connection (default: smtp)
                               Implemented protocols: smtp, lmtp, ldap
cert_domainname             -- Common Name as contained in the certificate
cert_domainname_validation  -- Type of validation of the cert domain name (default: None)
                               Allowed values: None, cn, cn_san

Ref.: https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
"""

import json
import sys
import re
import ssl
import socket
import select
import datetime
from enum import Enum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from paesslerag_prtg_sensor_api.sensor.result import CustomSensorResult
from paesslerag_prtg_sensor_api.sensor.units import ValueUnit

class Protocol(Enum):
    """Application Layer protocols
    """
    SMTP = 1
    LMTP = 2
    IMAP = 3
    LDAP = 4

class Validation(Enum):
    """Certificate Name validations
    """
    NONE = 1
    CN = 2
    CN_SAN = 3

def prtg_params_dict(params: str) -> dict:
    """
    prtg_params_dict - Converts a PRTG params string into a dictionary.

    It takes the params string and converts it via json into a dictionary. The solution is based
    on Stack Overflow (https://stackoverflow.com/questions/47663809/python-convert-string-to-dict)
    """

    _params = '{' + params.strip() + '}'
    _params_json_string = ''

    # Remove surrounding spaces arround separator chars
    _params_stripped = re.sub(r'\s*([:,])\s*', r'\g<1>', _params)
    _params_json_string = re.sub(r'([:,])', r'"\g<1>"', _params_stripped)
    _params_json_string = re.sub(r'{', r'{"', _params_json_string)
    _params_json_string = re.sub(r'}', r'"}', _params_json_string)

    return json.loads(_params_json_string)

def starttls_getpeercert(address,
                         starttls_proto: Protocol,
                         cert_hostname=None,
                         timeout=3.0, msglen=4096) -> dict:
    """
    starttls_getpeercert - Retrieves the certificate of the other side of the connection.

    @Returns: Certificate dict with selfSigned? and rootAuthorityTrusted? mixed in.

    @NOTE: Dictionary keys:
        subject (string; distinguished name form)
        issuer (string; distinguished name form)
        version (int)
        serialNumber (hex string; w/o leading 0x)
        notBefor (datetime)
        notAfter (datetime)
        fingerprint (hex string; w/o leading 0x)
        commonName (string; w/o CN=)
        publicKeySize (int)
        subjectAltName (list of tuples: type, value; optional)
        crlDistributionPoints (list of URIs; optional)
        OCSP (URI; optional)
        caIssuers (URI; optional)
        selfSigned? (boolean)
        rootAuthorityTrusted? (boolean)

    Ref: https://stackoverflow.com/questions/5108681/use-python-to-get-an-smtp-server-certificate
    REf: https://stackoverflow.com/questions/71114085/how-can-i-retrieve-openldap-servers-starttls-
         certificate-with-pythons-ssl-libr
    """

    if cert_hostname is None:
        sni_hostname = address[0]
    else:
        sni_hostname = cert_hostname

    # Request #1: Get certificate data (incl. self-issued certs) with verify_mode set to CERT_NONE
    # in the created context
    # The SSLContext is created with the class constructor since retrieving self-signed certs
    # require loosened SSL settings. To fetch self-signed certs verify_mode MUST be set to
    # CERT_NONE which requires disabling hostname checking.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_sock = _starttls_do_service_handshake(address,
                                              starttls_proto,
                                              timeout=timeout,
                                              msglen=msglen)
    with ctx.wrap_socket(raw_sock, server_hostname=sni_hostname) as ssl_sock:
        cert_der = ssl_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    raw_sock.close()
    cert_dict = _starttls_cert_dict(cert)
    cert_dict['selfSigned?'] = (cert_dict['subject'] == cert_dict['issuer'])

    # Request #2: Verify root authority trust and certificate chain
    if cert_dict['selfSigned?']:
        cert_dict['rootAuthorityTrusted?'] = False
    else:
        ctx = ssl.create_default_context()
        raw_sock = _starttls_do_service_handshake(address,
                                                  starttls_proto,
                                                  timeout=timeout,
                                                  msglen=msglen)
        try:
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni_hostname)
            cert_dict['rootAuthorityTrusted?'] = True
            ssl_sock.close()
        except ssl.SSLCertVerificationError:
            cert_dict['rootAuthorityTrusted?'] = False

    return cert_dict

def _starttls_do_service_handshake(address,
                                   starttls_proto: Protocol,
                                   timeout=3.0,
                                   msglen=4096) -> socket.socket:
    """
    starttls_do_service_handshake - Perform the service handshake to initiate a TLS connection

    @Returns: socket.socket
    """
    # Protocol.LDAP sends a LDAP_START_TLS_OID - sniffed with Wireshark
    protocol_greeters = {
        Protocol.SMTP: bytes(f'EHLO {socket.gethostname()}\nSTARTTLS\n', 'ascii'),
        Protocol.LMTP: bytes(f'LHLO {socket.gethostname()}\nSTARTTLS\n', 'ascii'),
        Protocol.LDAP: b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31\x2e\x33\x2e\x36\x2e\x31' \
                       b'\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37'
    }
    protocol_greeting = protocol_greeters.get(starttls_proto, protocol_greeters[Protocol.SMTP])

    raw_sock = socket.create_connection(address, timeout)
    # Send protocol related greeting to initiate STARTTLS
    # Protocol.SMTP and Protocol.LMTP
    if starttls_proto in [Protocol.SMTP, Protocol.LMTP]:
        raw_sock.recv(msglen)
        raw_sock.send(protocol_greeting)
        raw_sock.recv(msglen)
        # Debugging this script and stepping thru the statements catches all data sent
        # by the server, but running normaly requires an additional read before creating
        # the SSL socket - omitting the following block would throw a SSLError: WRONG_VERSION_NUMBER
        _raw_sock_ready = select.select([raw_sock], [], [], (timeout / 10))
        if _raw_sock_ready[0]:
            raw_sock.recv(msglen)

    # Protocol.LDAP
    if starttls_proto == Protocol.LDAP:
        raw_sock.send(protocol_greeting)
        # Look for \x0a\x01 {result code} \x04\x00\x04\x00 - if the second \x04 is not followed
        # by \x00 then it seems that the server support STARTTLS but has no cert installed
        _ldap_response = raw_sock.recv(msglen)
        _ldap_response_result_pos = _ldap_response.find(b'\x0a\x01')
        _ldap_response_result_trail = _ldap_response.find(b'\x04\x00\x04\x00',
                                                          _ldap_response_result_pos)

        if not(_ldap_response_result_trail - _ldap_response_result_pos == 3 and
                _ldap_response[_ldap_response_result_pos + 2] == 0):
            raw_sock.close()
            _err_msg = "LDAP Server does not support LDAP_START_TLS_OID "
            _err_msg += "or has no certificate installed."
            raise OSError(_err_msg)

    return raw_sock

def _starttls_cert_dict(cert) -> dict:
    """
    starttls_cert_dict - Converts a <Certificate> object into a <dict> object

    The dict object contains the keys `subject`, `issuer`, `version`, `serialNumber`,
    `notBefore`, `notAfter`, `subjectAltName`, `OCSP`, `caIssuers`, and `crlDistributionPoints`.

    Mixed-in are `commonName`, `fingerprint` (SHA1), and `publicKeySize`
    """

     # Cert basic data
    cert_dict = {}
    cert_dict['subject'] = cert.subject.rfc4514_string()
    cert_dict['issuer'] = cert.issuer.rfc4514_string()
    cert_dict['version'] = cert.version.value
    cert_dict['serialNumber'] = hex(cert.serial_number).replace('0x', '').upper()
    cert_dict['notBefore'] = cert.not_valid_before
    cert_dict['notAfter'] = cert.not_valid_after
    cert_dict['fingerprint'] = cert.fingerprint(hashes.SHA1()).hex().upper()
    cert_dict['commonName'] = cert.subject.rfc4514_string().split(',')[0].split('=')[1]
    cert_dict['publicKeySize'] = cert.public_key().key_size

    # Cert extension data - subjectAltName: looking only for values of type DNSName
    #                       crlDistributionPoints
    _extension_oids = [
        (x509.ObjectIdentifier('2.5.29.17'), 'subjectAltName'),
        (x509.ObjectIdentifier('2.5.29.31'), 'crlDistributionPoints'),
    ]
    for _extension_oid, _dict_key in _extension_oids:
        try:
            _extension = cert.extensions.get_extension_for_oid(_extension_oid)
            if _dict_key == 'subjectAltName':
                _extension_subject_alt_names = _extension.value.get_values_for_type(x509.DNSName)
                cert_dict[_dict_key] = [ ('DNS', _name) for _name in _extension_subject_alt_names ]
            if _dict_key == 'crlDistributionPoints':
                cert_dict[_dict_key] = [ _crldp.full_name[0].value for _crldp in _extension.value ]
        except x509.ExtensionNotFound:
            pass

    # Cert extension data - Authority Access Info Methods (OCSP, caIssuers)
    _extension_oid = x509.ObjectIdentifier('1.3.6.1.5.5.7.1.1')
    _authority_access_method_oids = [
        (x509.ObjectIdentifier('1.3.6.1.5.5.7.48.1'), 'OCSP'),
        (x509.ObjectIdentifier('1.3.6.1.5.5.7.48.2'), 'caIssuers'),
    ]
    try:
        _extension = cert.extensions.get_extension_for_oid(_extension_oid)
        while len(_authority_access_method_oids) > 0:
            _access_method_oid, _dict_key = _authority_access_method_oids.pop(0)
            for _access_description in _extension.value:
                if _access_description.access_method == _access_method_oid:
                    cert_dict[_dict_key] = _access_description.access_location.value
                    break
    except x509.ExtensionNotFound:
        pass

    return cert_dict

def _prtg_cert_cncheck_result(certificate: dict,
                              validation_mode: Validation,
                              cert_hostname: str) -> int:
    """
    prtg_cert_cncheck_result - Returns the proper result value based on cert_domainname_validation

    The return value matches the expected result specified in the default overlay
    prtg.standardlookups.sslcertificatesensor.cncheck.
    This script DOES NOT return all values since SNI check and common_name check
    are considered interchangeable.

    Expected result values defined in overlay:
        Value 0: State Ok, Matches device address (Validation mode: cn)
        Value 1: State Error, Does not match device address (Validation mode: cn)
        Value 2: State Ok, Disabled (Validation mode: None)
        Value 5: State Ok, CN/SAN match (Validation mode: cn_san)
        Value 6: State Error, CN/SAN do not match SNI

    @Returns: int
    """
    result_value = 2

    if validation_mode == Validation.CN:
        if cert_hostname.strip().lower() == certificate["commonName"].strip().lower():
            result_value = 0
        else:
            result_value = 1
    if validation_mode == Validation.CN_SAN:
        if cert_hostname.strip().lower() == certificate["commonName"].strip().lower():
            result_value = 5
        if "subjectAltName" in certificate.keys():
            _names = [_tuple[1] for _tuple in certificate["subjectAltName"] if _tuple[0] == "DNS"]
            if cert_hostname.strip().lower() in _names:
                result_value = 5
        # If after all checks result_value is still 2 (disabled) - correct it to the error value
        if result_value == 2:
            result_value = 6

    return result_value


def main():
    """
    starttls_certificate_sensor - Monitors the certificate of a STARTTLS-secured connection

    Monitors the SSL certificate of services that require the client to issue a STARTTLS command
    in order to start a secure connection.
    """
    try:
        # Basic argument check
        if len(sys.argv) < 2:
            raise TypeError("JSON object argument missing.")
        data = json.loads(sys.argv[1])

        if "params" not in data.keys():
            raise TypeError("Key 'params' missing in JSON object.")
        params = prtg_params_dict(data["params"])

        _now = datetime.datetime.now()
        cert = starttls_getpeercert((data["host"], int(params.get("port", "25"))),
                                    Protocol[params.get("protocol", "smtp").upper()],
                                    cert_hostname=params.get("cert_domainname", data["host"]))

        csr_text_ok = "OK. Certificate Common Name: {} - "
        csr_text_ok += "Certificate Thumbprint: {} - "
        csr_text_ok += "STARTTLS Protocol: {}"
        csr = CustomSensorResult(text=csr_text_ok.format(cert['commonName'],
                                                         cert['fingerprint'],
                                                         params.get('protocol', "smtp").upper()))
        # Channel _Days to Expiration_ (Primary)
        _prtg_expirationcheck_value = (cert['notAfter'] - _now).days
        csr.add_primary_channel(name="Days to Expiration",
                        value=_prtg_expirationcheck_value,
                        unit=ValueUnit.COUNT,
                        is_float=False,
                        is_limit_mode=True,
                        limit_min_error=17,
                        limit_min_warning=35,
                        limit_error_msg="Certificate will expire in less than 17 days.",
                        limit_warning_msg="Certificate will expire soon.")

        # Channel _Common Name Check_
        _validation = Validation[params.get("cert_domainname_validation", "NONE").upper()]
        _sni_domainname = params.get("cert_domainname", data["host"])
        _prtg_cncheck_value = _prtg_cert_cncheck_result(cert, _validation, _sni_domainname)
        csr.add_channel(name="Common Name Check",
                        unit=ValueUnit.CUSTOM,
                        value_lookup='prtg.standardlookups.sslcertificatesensor.cncheck',
                        value=_prtg_cncheck_value,
                        is_float=False,
                        is_limit_mode=False)

        # Channel _Public Key Length_
        _prtg_publickeycheck_value = cert["publicKeySize"]
        csr.add_channel(name="Public Key Length",
                unit=ValueUnit.CUSTOM,
                value_lookup='prtg.standardlookups.sslcertificatesensor.publickey',
                value=_prtg_publickeycheck_value,
                is_float=False,
                is_limit_mode=False)

        # Channel _Revoked_ - not implemented

        # Channel _Root Authority Trusted_ - checks trust AND chain
        _prtg_trustedrootcheck_value = 0
        if not cert["rootAuthorityTrusted?"]:
            _prtg_trustedrootcheck_value = 1
        csr.add_channel(name="Root Authority Trusted",
                unit=ValueUnit.CUSTOM,
                value_lookup='prtg.standardlookups.sslcertificatesensor.trustedroot',
                value=_prtg_trustedrootcheck_value,
                is_float=False,
                is_limit_mode=False)

        # Channel _Self-Signed_
        _prtg_selfsignedcheck_value = 0
        if cert['selfSigned?']:
            _prtg_selfsignedcheck_value = 1
        csr.add_channel(name="Self-Signed",
                unit=ValueUnit.CUSTOM,
                value_lookup='prtg.standardlookups.sslcertificatesensor.selfsigned',
                value=_prtg_selfsignedcheck_value,
                is_float=False,
                is_limit_mode=False)

    except json.JSONDecodeError as sensor_error:
        csr = CustomSensorResult(text="Python Script execution error")
        csr.error = f"Failed to decode 'params' into valid JSON object: {str(sensor_error)}"
    except KeyError as sensor_error:
        csr = CustomSensorResult(text="Python Script execution error")
        csr.error = f"Invalid key in 'protocol'|'cert_domainname_validation': {str(sensor_error)}"
    except ssl.SSLEOFError as sensor_error:
        csr = CustomSensorResult(text="Python Script execution error")
        csr.error = f"Protocol handshake prior to STARTTLS possibly failed': {str(sensor_error)}"
    except (TypeError, OSError, RuntimeError) as sensor_error:
        csr = CustomSensorResult(text="Python Script execution error")
        csr.error = f"Python Script runtime error: {str(sensor_error)}"

    finally:
        # Print sensor JSON result
        print(csr.json_result)

if __name__ == "__main__":
    main()
