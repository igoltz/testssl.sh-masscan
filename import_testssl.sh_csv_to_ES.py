#!/usr/bin/python3
# Import testssl.sh CSV to ELasticSearch

import argparse
from docTestssl import DocTestSSLResult
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl import Index
from datetime import datetime

argparser = argparse.ArgumentParser(description="Import testssl.sh CSV logs into ElasticSearch")
argparser.add_argument("--elasticsearch", "-e", nargs="*", default="localhost", help="ElasticSearch host (default: %(default)s)")
argparser.add_argument("--index", "-i", default="testssl-scan", help="ElasticSearch index (default: %(default)s)")
argparser.add_argument("--ca_cert", "-c", help="ElasticSearch CA certificate")
argparser.add_argument("files", nargs="+", help="List of testssl.sh logs in CSV format")
args = argparser.parse_args()

connections.create_connection(hosts=args.elasticsearch,ca_certs=args.ca_cert)
idx = Index(args.index)
idx.document(DocTestSSLResult)
DocTestSSLResult.init()
try:
    idx.create()
except:
    pass

csvFiles = args.files
for csvFile in csvFiles:
    try:
        csv = open(csvFile, mode="r", newline="")
    except IOError as e:
        print("Error while opening %s: %s" % (csvFile, e.strerror))

    print("Processing '%s'" % (csvFile))
    doc = DocTestSSLResult(source=csvFile)
    doc.parseCSV(csv)
    csv.close()
    try:
        doc.save()
    except ValueError:
        print("File %s was empty!" % (csvFile))
