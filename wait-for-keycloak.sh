#!/bin/sh
# wait-for-keycloak.sh

set -e

 
while [ $(curl -s -o response.txt -w "%{http_code}" http://keycloak-dev:8080/health/live) -ne  200 ];
do
  >&2 echo "Keycloak is unavailable - retrying"
  sleep 1
done

sh /opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties

>&2 echo "Keycloak is up"

#exec "$@"