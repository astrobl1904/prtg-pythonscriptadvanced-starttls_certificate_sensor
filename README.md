# prtg-pythonscriptadvanced-starttls_certificate_sensor

This repository contains a PRTG Python Script Advanced sensor to monitor SSL Certificates of a SSL/TLS secured connections which require STARTTLS to initialize a secure channel.

## Sensor Summary

    Script Language: Python 3.7+
    Version: 0.1.0
    Author: Andreas Strobl <astroblx@asgraphics.at>
    Dependencies: cryptography >=37.0.0

## Sensor Description

This custom _Python Script Advanced_ sensor will monitor SSL certificates that require a protocol handshake prior to reading certificate data, and exposes the collected data in channels similar to PRTG's built-in _SSL Certificate_ sensor.

As of version v0.1.0 this sensor supports the following application layer protocols:

* `SMTP`: Simple Mail Transfer Protocol, [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)
* `LMTP`: Local Mail Transfer Protocol, [RFC 2033](https://datatracker.ietf.org/doc/html/rfc2033)
* `LDAP`: Lightweight Directory Access Protocol, [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511)

The _LDAP_ protocol handshake has been tested against _Active Directory_, _OpenLDAP_, and _Sun Enterprise Directory Server_ (formerly _Netscape iPlanet Directory Server_) and is also expected to work with _RedHat DS 389_ directory server.

## Sensor Channels

The following channels are implemented:

* `Days until Expiration` - primary channel
* `Common Name Check` - with support for CN and CN/SAN validation
* `Public Key Size`
* `Root Authority Trusted`
* `Self-Signed`

All channels but the primary channel use PRTG built-in value lookup definitions.

### Common Name Check

PRTGs built-in _SSL Certificate_ sensor allows also to validate `SNI Domainname` values. Since this is in essence a check of an user-specified domain name against the _commonName_ and/or _subjectAltName_ attribute of the certificate, this sensor ommits the result values _SNI Domainname matches_ and _SNI Domainname does not match_.

If the device's network address is specified as domain name and is the same as contained in the certificate, the parameter `cert_domainname` can be omitted.

### Root Authority Trusted

This check uses the default mechanisms of the Python `ssl` module to verify the trust of the certificate. This includes the check of the chain and also that the root CA certificate is in the operating system vendor's certificate store.

One implication of this kind of validation is that it fails if the certificate chain is incorrect and also fails if the root CA certificate is not in the trust store of the system the probe is running on.

The check is skipped entirely if the installed certificate is a self-signed certificate. In this case the channel result is set to _Not trusted_.

## Sensor Parameters

The sensor expects parameters that specify application protocol, port, and certificate name validation. Without those additional parameters the sensor returns an error result.

The parameters MUST be specified in form of key-value pairs with key and value separated by a colon. Multiple key-value pairs are separated by a comma.

The parameter string MUST NOT contain quotes, braces, brackets, and parens. It also MUST NOT contain characters outside the ASCII character set, and it MUST NOT contain the + sign. Use of any of those characters and symbols will cause PRTG to excessively escape those characters, leading to a lot of backslashes in the parameter string, which this sensor DOES NOT handle well.

### Parameter `port` (int)

This parameter specifies the port the sensor should connect to.

### Parameter `protocol` (Enum)

This parameter specifies the application protocol to be used to initiate a secure connection with _STARTTLS_.

Allowed values are: `smtp`, `lmtp`, and `ldap`.

### Parameter `cert_domainname` (str)

If the device address is specified as IP address or if the device name differs from the name used in the certificate, specify the name contained in the certificate with this parameter.

### Parameter `cert_domainname_validation` (Enum)

This parameter tells the sensor if and how it should validate `commonName` and/or `subjectAltName` certificate attributes.

Allowed values:

* `None`: do not validate names
* `cn`: validate the domain name against the certificate's _commonName_ attribute
* `cn_san`: validate the domain name against the certificate's _commonName_ and _subjectAltName_ attributes. With _subjectAltName_ only values of type _DNS_ are validated.

### Examples

1. The following parameter string validates the certificate of a mail server listening on port 7025 and expecting the _LMTP_ protocol. The certificate contains multiple names in the _subjectAltName_ attribute, the device address is specified as domain name and is contained in the _subjectAltName_ attribute:

    `port: 7025, protocol: lmtp, cert_domainname_validation: cn_san`

1. In this example the device address is specified as IP address, the server is a mail server listening on port 25 with the _SMTP_ protocol:

    `port: 25, protocol: smtp, cert_domainname: mta.example.com, cert_domainname_validation: cn`
