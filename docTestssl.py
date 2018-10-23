#!/usr/bin/python3
# Import testssl.sh CSV to ELasticSearch

from elasticsearch_dsl import DocType, Object, Date, Keyword, Integer, Short, Boolean
from datetime import datetime
from tzlocal import get_localzone
import csv
import re
import pprint     # for debugging purposes only

pp = pprint.PrettyPrinter(indent=4)

tz = get_localzone()
reDefaultFilename = re.compile("(?:^|/)(?P<ip>\d+\.\d+\.\d+\.\d+)(:(?P<port>\d+))?-(?P<datetime>\d{8}-\d{4})\.csv$")
reProtocol = re.compile("^(?:SSLv\\d|TLS\\d(?:_\\d)?)$")
reCipherTests = re.compile("^std_(.*)$")
reIpHostColumn = re.compile("^(.*)/(.*)$")
reCipherColumnName = re.compile("^cipher_")
reCipherDetails = re.compile("^\\S+\\s+(\\S+)")
reCipherTests = re.compile("^std_(.*)$")
reDefaultProtocol = re.compile("^Default protocol (\\S+)")
reDefaultCipher = re.compile("^Default cipher: (.*?)(?:$|[,\\s])")
reKeySize = re.compile("Server Keys (\\d+) bits")
reSignAlgorithm = re.compile("Signature Algorithm: (.*)\\s\\(")
reFPMD5 = re.compile("MD5 (\\S+)")
reFPSHA1 = re.compile("SHA1 (\\S+)")
reFPSHA256 = re.compile("SHA256 (\\S+)")
reCN = re.compile("^(.*?)[\\s\\(]")
reSAN = re.compile(": (.*)$")
reIssuer = re.compile("'issuer= (.*?)' \\(")
reExpiration = re.compile("--> (.*)\\)")
reOCSPURI = re.compile(" : (?!--)(.*)")

reOffers = re.compile("(?<!not )offered")
reNotOffered = re.compile("not offered")
reOk = re.compile("\\(OK\\)")
reYes = re.compile("yes", re.IGNORECASE)
reVulnerable = re.compile("\\(NOT ok\\)", re.IGNORECASE)

class DocTestSSLResult(DocType):

    source = Keyword(fields={'raw': Keyword()})
    result = Boolean()
    timestamp = Date()
    ip = Keyword()
    hostname = Keyword()
    port = Integer()
    svcid = Keyword()
    protocols = Keyword(multi=True)
    ciphers = Keyword(multi=True, fields={'raw': Keyword()})
    ciphertests = Keyword(multi=True)
    serverpref = Object(
            properties = {
                "cipher_order": Boolean(),
                "protocol": Keyword(),
                "cipher": Keyword(fields={'raw': Keyword()})
                })
    cert = Object(
            properties = {
                "keysize": Keyword(),
                "signalgo": Keyword(fields={'raw': Keyword()}),
                "md5_fingerprint": Keyword(),
                "sha1_fingerprint": Keyword(),
                "sha256_fingerprint": Keyword(),
                "cn": Keyword(fields={'raw': Keyword()}),
                "san": Keyword(multi=True, fields={'raw': Keyword()}),
                "issuer": Keyword(fields={'raw': Keyword()}),
                "ev": Boolean(),
                "expiration": Keyword(fields={'raw': Keyword()}),
                "ocsp_uri": Keyword(fields={'raw': Keyword()}),
                "ocsp_stapling": Boolean(),
                })
    vulnerabilities = Keyword(multi=True)

    def parseCSVLine(self, line):
        if line['id'] == "id":
            return
        if not self.ip or not self.hostname or not self.port:   # host, ip and port
            m = reIpHostColumn.search(line['fqdn/ip'])
            if m:
                self.hostname, self.ip = m.groups()
            self.port = int(line['port'])

        if reProtocol.search(line['id']) and reOffers.search(line['finding']):     # protocols
            self.result = True
            m = reProtocol.search(line['id'])
            if m:
                self.protocols.append(line['id'].upper())
        elif reCipherColumnName.search(line['id']):                  # ciphers
            m = reCipherDetails.search(line['finding'])
            if m:
                self.ciphers.append(m.group(1))
        elif reCipherTests.search(line['id']) and reVulnerable.search(line['finding']):                       # cipher tests
            m = reCipherTests.search(line['id'])
            if m:
                self.ciphertests.append(m.group(1))
        elif line['id'] == "order":                                 # server prefers cipher
            self.serverpref.cipher_order = bool(reOk.search(line['finding']))
        elif line['id'] == "protocol_negotiated":                           # preferred protocol
            self.serverpref.protocol = line['finding']
        elif line['id'] == "cipher_negotiated":                          # preferred cipher
            self.serverpref.cipher = line['finding']
        elif line['id'] == "cert_keySize":                              # certificate key size
            self.cert.keysize = line['finding']
        elif line['id'] == "cert_signatureAlgorithm":                             # certificate sign algorithm
            self.cert.signalgo = line['finding']
        elif line['id'] == "cert_fingerprintSHA1":                           # certificate fingerprints
            self.cert.sha1_fingerprint = line['finding']
        elif line['id'] == "cert_fingerprintSHA256":
            self.cert.sha256_fingerprint = line['finding']
        elif line['id'] == "cert_commonName":                                    # certificate CN
            self.cert.cn = line['finding']
        elif line['id'] == "cert_subjectAltName":                                   # certificate SAN
            sans = line['finding']
            for san in sans.split(" "):
                if san != "--":
                    self.cert.san.append(san)
        elif line['id'] == "cert_caIssuers":                                # certificate issuer
            self.cert.issuer = line['finding']
        elif line['id'] == "cert_certificatePolicies_EV":                                    # certificate extended validation
            self.cert.ev = bool(reYes.search(line['finding']))
        elif line['id'] == "cert_expiration_status":                            # certificate expiration
            self.cert.expiration = line['finding']
        elif line['id'] == "cert_ocspURL":                              # certificate OCSP URI
            self.cert.ocsp_uri = line['finding']
        elif line['id'] == "OCSP_stapling":                         # certificate OCSP stapling
            self.cert.ocsp_stapling = not bool(reNotOffered.search(line['finding']))
        elif line['id'] in ("heartbleed", "ccs", "secure_renego", "sec_client_renego", "crime", "breach", "poodle_ssl", "fallback_scsv", "freak", "DROWN", "logjam", "beast", "rc4") and reVulnerable.search(line['finding']):
            self.vulnerabilities.append(line['id'].upper())

    def parseCSV(self, csvfile):
        if self.source:
            m = reDefaultFilename.search(self.source)
            if m:
                self.ip = m.group('ip')
                self.port = int(m.group('port') or 0)
                self.timestamp = datetime.strptime(m.group('datetime'), "%Y%m%d-%H%M")
        csvReader = csv.DictReader(csvfile, fieldnames=("id", "fqdn/ip", "port", "severity", "finding", "cve", "cwe"), delimiter=',', quotechar='"')
        for line in csvReader:
            self.parseCSVLine(line)

    def save(self, **kwargs):
        if not self.timestamp:
            self.timestamp = datetime.now(tz)
        if not self.port:
            raise ValueError("Empty scan result")

        self.svcid = "%s:%d" % (self.ip, int(self.port) or 0)
        if not self.result:
            self.result = False

        if 'debug' in kwargs and kwargs['debug']:
            pp.pprint(self.to_dict())
        return super().save()
