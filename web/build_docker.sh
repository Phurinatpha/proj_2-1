#!/bin/sh
app="docker.test"
docker build -t ${app} .
docker run -p 56799:8000 -d \
  --name=${app} \
  -v $PWD:/app ${app}