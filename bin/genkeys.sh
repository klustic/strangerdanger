#!/bin/bash
BASE="$(cd $(dirname $0) && cd .. && pwd -P)"
CERT="${BASE}/cert.pem"
KEY="${BASE}/key.pem"

openssl req -x509 -newkey rsa:4096 -keyout "${KEY}" -out "${CERT}" -nodes
