===============
pyramid_macauth
===============

This is a Pyramid authenitcation plugin for MAC Access Authentication:

    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

To access resources using MAC Access Authentication, the client must have
obtained a set of MAC credentials including an id and secret key.  They use
these credentials to make signed requests to the server.

When accessing a protected resource, the server will generate a 401 challenge
response with the scheme "MAC" as follows::

    > GET /protected_resource HTTP/1.1
    > Host: example.com

    < HTTP/1.1 401 Unauthorized
    < WWW-Authenticate: MAC

The client will use their MAC credentials to build a request signature and
include it in the Authorization header like so::

    > GET /protected_resource HTTP/1.1
    > Host: example.com
    > Authorization: MAC id="h480djs93hd8",
    >                    ts="1336363200",
    >                    nonce="dj83hs9s",
    >                    mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

    < HTTP/1.1 200 OK
    < Content-Type: text/plain
    <
    < For your eyes only:  secret data!


This plugin uses the tokenlib library for verifying MAC credentials:

    https://github.com/mozilla-services/tokenlib

If this library does not meet your needs, you can provide a custom callback
function to decode the MAC id token.
