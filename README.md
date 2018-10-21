# thingy.jp selfservice

This is a small Flask app that implements a few endpoints to allow users
to request things like client certificates that are required to connect
to the thingy.jp public broker.

## Running locally

Run before the first run use ```setupca.sh``` and ```server_createcert.sh```
to create a local CA setup and a server cert for the service to use.
Next run ```runlocally.sh``` to start up a local instance.
