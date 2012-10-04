# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest
import json
import time

from webtest import TestApp

from zope.interface.verify import verifyClass

from pyramid.request import Request
from pyramid.response import Response
from pyramid.config import Configurator
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPUnauthorized
from pyramid.security import (unauthenticated_userid,
                              authenticated_userid,
                              effective_principals,
                              Everyone,
                              Authenticated)

import macauthlib

from pyramid_macauth import MACAuthenticationPolicy


def make_request(config, path="/", environ={}):
    """Helper function for making pyramid Request objects."""
    my_environ = {}
    my_environ["wsgi.version"] = (1, 0)
    my_environ["wsgi.multithread"] = True
    my_environ["wsgi.multiprocess"] = True
    my_environ["wsgi.run_once"] = False
    my_environ["wsgi.url_scheme"] = "http"
    my_environ["REQUEST_METHOD"] = "GET"
    my_environ["SCRIPT_NAME"] = ""
    my_environ["PATH_INFO"] = path
    my_environ["SERVER_NAME"] = "localhost"
    my_environ["SERVER_PORT"] = "5000"
    my_environ["QUERY_STRING"] = "5000"
    my_environ.update(environ)
    request = Request(my_environ)
    request.registry = config.registry
    return request


# Something non-callable, to test loading non-callables by name.
stub_non_callable = None


def stub_find_groups(userid, request):
    """Groupfinder with the following rules:

        * any user with "bad" in their name is invalid
        * the "test" user belongs to group "group"
        * all other users have no groups

    """
    if "bad" in userid:
        return None
    if userid == "test":
        return ["group"]
    return []


def stub_view_public(request):
    """Stub view that returns userid if logged in, None otherwise."""
    userid = unauthenticated_userid(request)
    return Response(str(userid))


def stub_view_auth(request):
    """Stub view that returns userid if logged in, fails if not."""
    userid = authenticated_userid(request)
    if userid is None:
        raise HTTPForbidden
    return Response(userid)


def stub_view_groups(request):
    """Stub view that returns groups if logged in, fails if not."""
    groups = effective_principals(request)
    return Response(json.dumps(map(str, groups)))


def stub_decode_mac_id(request, id, suffix="-SECRET"):
    """Stub mac-id-decoding function that appends suffix to give the secret."""
    return id, id + suffix


def stub_encode_mac_id(request, id, suffix="-SECRET"):
    """Stub mac-id-encoding function that appends suffix to give the secret."""
    return id, id + suffix


class TestMACAuthenticationPolicy(unittest.TestCase):
    """Testcases for the MACAuthenticationPolicy class."""

    def setUp(self):
        self.config = Configurator(settings={
            "macauth.find_groups": "pyramid_macauth.tests:stub_find_groups",
        })
        self.config.include("pyramid_macauth")
        self.config.add_route("public", "/public")
        self.config.add_view(stub_view_public, route_name="public")
        self.config.add_route("auth", "/auth")
        self.config.add_view(stub_view_auth, route_name="auth")
        self.config.add_route("groups", "/groups")
        self.config.add_view(stub_view_groups, route_name="groups")
        self.app = TestApp(self.config.make_wsgi_app())
        self.policy = self.config.registry.queryUtility(IAuthenticationPolicy)

    def _make_request(self, *args, **kwds):
        return make_request(self.config, *args, **kwds)

    def _make_signed_request(self, userid, *args, **kwds):
        req = self._make_request(*args, **kwds)
        creds = self._get_credentials(req, userid=userid)
        macauthlib.sign_request(req, **creds)
        return req

    def _get_credentials(self, req, **data):
        id, key = self.policy.encode_mac_id(req, **data)
        return {"id": id, "key": key}

    def test_the_class_implements_auth_policy_interface(self):
        verifyClass(IAuthenticationPolicy, MACAuthenticationPolicy)

    def test_from_settings_can_explicitly_set_all_properties(self):
        policy = MACAuthenticationPolicy.from_settings({
          "macauth.find_groups": "pyramid_macauth.tests:stub_find_groups",
          "macauth.master_secret": "V8 JUICE IS 1/8TH GASOLINE",
          "macauth.nonce_cache": "macauthlib:NonceCache",
          "macauth.decode_mac_id": "pyramid_macauth.tests:stub_decode_mac_id",
          "macauth.encode_mac_id": "pyramid_macauth.tests:stub_encode_mac_id",
        })
        self.assertEquals(policy.find_groups, stub_find_groups)
        self.assertEquals(policy.master_secret, "V8 JUICE IS 1/8TH GASOLINE")
        self.assertTrue(isinstance(policy.nonce_cache, macauthlib.NonceCache))
        self.assertEquals(policy.decode_mac_id, stub_decode_mac_id)
        self.assertEquals(policy.encode_mac_id, stub_encode_mac_id)

    def test_from_settings_passes_on_args_to_nonce_cache(self):
        policy = MACAuthenticationPolicy.from_settings({
          "macauth.nonce_cache": "macauthlib:NonceCache",
          "macauth.nonce_cache_nonce_ttl": 42,
        })
        self.assertTrue(isinstance(policy.nonce_cache, macauthlib.NonceCache))
        self.assertEquals(policy.nonce_cache.nonce_ttl, 42)
        self.assertRaises(TypeError, MACAuthenticationPolicy.from_settings, {
          "macauth.nonce_cache": "macauthlib:NonceCache",
          "macauth.nonce_cache_invalid_arg": "WHAWHAWHAWHA",
        })

    def test_from_settings_errors_out_on_unexpected_keyword_args(self):
        self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
          "macauth.unexpected": "spanish-inquisition",
        })

    def test_from_settings_errors_out_on_args_to_a_non_callable(self):
        self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
          "macauth.nonce_cache": "pyramid_macauth.tests:stub_non_callable",
          "macauth.nonce_cache_arg": "invalidarg",
        })

    def test_from_settings_errors_out_if_decode_mac_id_is_not_callable(self):
        self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
          "macauth.decode_mac_id": "pyramid_macauth.tests:stub_non_callable",
        })

    def test_from_settings_errors_out_if_encode_mac_id_is_not_callable(self):
        self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
          "macauth.encode_mac_id": "pyramid_macauth.tests:stub_non_callable",
        })

    def test_from_settings_produces_sensible_defaults(self):
        policy = MACAuthenticationPolicy.from_settings({})
        self.assertEquals(policy.find_groups.im_func,
                          MACAuthenticationPolicy.find_groups.im_func)
        self.assertEquals(policy.decode_mac_id.im_func,
                          MACAuthenticationPolicy.decode_mac_id.im_func)
        self.assertTrue(isinstance(policy.nonce_cache, macauthlib.NonceCache))

    def test_from_settings_curries_args_to_decode_mac_id(self):
        policy = MACAuthenticationPolicy.from_settings({
          "macauth.decode_mac_id": "pyramid_macauth.tests:stub_decode_mac_id",
          "macauth.decode_mac_id_suffix": "-TEST",
        })
        self.assertEquals(policy.decode_mac_id(None, "id"), ("id", "id-TEST"))

    def test_from_settings_curries_args_to_encode_mac_id(self):
        policy = MACAuthenticationPolicy.from_settings({
          "macauth.encode_mac_id": "pyramid_macauth.tests:stub_encode_mac_id",
          "macauth.encode_mac_id_suffix": "-TEST",
        })
        self.assertEquals(policy.encode_mac_id(None, "id"), ("id", "id-TEST"))

    def test_remember_does_nothing(self):
        policy = MACAuthenticationPolicy()
        req = self._make_signed_request("test@moz.com", "/")
        self.assertEquals(policy.remember(req, "test@moz.com"), [])

    def test_forget_gives_a_challenge_header(self):
        policy = MACAuthenticationPolicy()
        req = self._make_signed_request("test@moz.com", "/")
        headers = policy.forget(req)
        self.assertEquals(len(headers), 1)
        self.assertEquals(headers[0][0], "WWW-Authenticate")
        self.assertTrue(headers[0][1] == "MAC")

    def test_unauthenticated_requests_get_a_challenge(self):
        r = self.app.get("/auth", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("MAC"))

    def test_authenticated_request_works(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")

    def test_authentication_fails_when_macid_has_no_userid(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, hello="world")
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_non_mac_scheme_fails(self):
        req = self._make_request("/auth")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=401)
        req = self._make_request("/public")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=200)

    def test_authentication_without_macid_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("id", "idd")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_timestamp_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("ts", "typostamp")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_nonce_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("nonce", "typonce")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_expired_timestamp_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=200)
        # Now do one with a really old timestamp.
        ts = str(int(time.time() - 1000))
        req.authorization = ("MAC", {"ts": ts})
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_far_future_timestamp_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        # Do an initial request so that the server can
        # calculate and cache our clock skew.
        ts = str(int(time.time()))
        req.authorization = ("MAC", {"ts": ts})
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=200)
        # Now do one with a far future timestamp.
        ts = str(int(time.time() + 1000))
        req.authorization = ("MAC", {"ts": ts})
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_reused_nonce_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        # First request with that nonce should succeed.
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        macauthlib.sign_request(req, **creds)
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")
        # Second request with that nonce should fail.
        req = self._make_request("/auth")
        req.authorization = ("MAC", {"nonce": "PEPPER"})
        macauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_busted_macid_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        id = macauthlib.utils.parse_authz_header(req)["id"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(id, "XXX" + id)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_busted_signature_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        macauthlib.sign_request(req, **creds)
        signature = macauthlib.utils.parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_groupfinder_can_block_authentication(self):
        req = self._make_signed_request("baduser", "/auth")
        r = self.app.request(req, status=401)
        req = self._make_signed_request("baduser", "/public")
        r = self.app.request(req, status=200)
        self.assertEquals(r.body, "baduser")

    def test_groupfinder_gruops_are_correctly_reported(self):
        req = self._make_request("/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          [str(Everyone)])
        req = self._make_signed_request("gooduser", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          ["gooduser", str(Everyone), str(Authenticated)])
        req = self._make_signed_request("test", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          ["test", str(Everyone), str(Authenticated), "group"])
        req = self._make_signed_request("baduser", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          [str(Everyone)])

    def test_access_to_public_urls(self):
        # Request with no credentials is allowed access.
        req = self._make_request("/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, "None")
        # Request with valid credentials is allowed access.
        req = self._make_signed_request("test@moz.com", "/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, "test@moz.com")
        # Request with invalid credentials still reports a userid.
        req = self._make_signed_request("test@moz.com", "/public")
        signature = macauthlib.utils.parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req)
        self.assertEquals(resp.body, "test@moz.com")
        # Request with malformed credentials gets a 401
        req = self._make_signed_request("test@moz.com", "/public")
        tokenid = macauthlib.utils.parse_authz_header(req)["id"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(tokenid, "XXX" + tokenid)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req, status=401)

    def test_check_signature_fails_if_no_params_present(self):
        req = self._make_request("/auth")
        self.assertRaises(HTTPUnauthorized,
                          self.policy._check_signature, req, "XXX")

    def test_default_groupfinder_returns_empty_list(self):
        policy = MACAuthenticationPolicy()
        req = self._make_request("/auth")
        self.assertEquals(policy.find_groups("test", req), [])

    def test_auth_can_be_checked_several_times_on_same_request(self):
        req = self._make_signed_request("test@moz.com", "/public")
        self.assertEquals(authenticated_userid(req), "test@moz.com")
        self.assertEquals(authenticated_userid(req), "test@moz.com")
