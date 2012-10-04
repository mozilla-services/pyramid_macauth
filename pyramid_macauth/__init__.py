# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A Pyramid authentication plugin for MAC Access Authentication:

    http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01

"""

__ver_major__ = 0
__ver_minor__ = 2
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


import functools

from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.util import DottedNameResolver

import tokenlib

import macauthlib
import macauthlib.utils


class MACAuthenticationPolicy(object):
    """Pyramid Authentication Policy implementing MAC Access Auth.

    This class provides an IAuthenticationPolicy implementation based on
    signed requests, using the MAC Access Authentication standard with
    pre-shared MAC credentials.

    The plugin can be customized with the following arguments:

        * find_groups:  a callable taking a userid and a Request object, and
                        returning a list of the groups that userid is a
                        member of.

        * master_secret:  a secret known only by the server, used for signing
                          MAC auth tokens in the default implementation.

        * decode_mac_id:  a callable taking a Request object and MAC token id,
                          and returning the userid and MAC secret key.

        * encode_mac_id:  a callable taking a Request object and userid, and
                          returning the MAC token id and secret key.

        * nonce_cache:  an object implementing the same interface as
                        macauthlib.NonceCache.

    """

    implements(IAuthenticationPolicy)

    # The default value of master_secret is None, which will cause tokenlib
    # to generate a fresh secret at application startup.
    master_secret = None

    def __init__(self, find_groups=None, master_secret=None, nonce_cache=None,
                 decode_mac_id=None, encode_mac_id=None):
        if find_groups is not None:
            self.find_groups = find_groups
        if master_secret is not None:
            self.master_secret = master_secret
        if nonce_cache is not None:
            self.nonce_cache = nonce_cache
        else:
            self.nonce_cache = macauthlib.NonceCache()
        if decode_mac_id is not None:
            self.decode_mac_id = decode_mac_id
        if encode_mac_id is not None:
            self.encode_mac_id = encode_mac_id

    @classmethod
    def from_settings(cls, settings={}, prefix="macauth.", **extra):
        """Construct a MACAuthenticationPolicy from deployment settings.

        This is a helper function for loading a MACAuthenticationPolicy from
        settings provided in the pyramid application registry.  It extracts
        settings with the given prefix, converts them to the appropriate type
        and passes them into the constructor.
        """
        # Grab out all the settings keys that start with our prefix.
        macauth_settings = {}
        for name, value in settings.iteritems():
            if not name.startswith(prefix):
                continue
            macauth_settings[name[len(prefix):]] = value
        # Update with any additional keyword arguments.
        macauth_settings.update(extra)
        # Pull out the expected keyword arguments.
        kwds = cls._parse_settings(macauth_settings)
        # Error out if there are unknown settings.
        for unknown_setting in macauth_settings:
            raise ValueError("unknown macauth setting: %s" % unknown_setting)
        # And finally we can finally create the object.
        return cls(**kwds)

    @classmethod
    def _parse_settings(cls, settings):
        """Parse settings for an instance of this class.

        This classmethod takes a dict of string settings and parses them into
        a dict of properly-typed keyword arguments, suitable for passing to
        the default constructor of this class.

        Implementations should remove each setting from the dict as it is
        processesed, so that any unsupported settings can be detected by the
        calling code.
        """
        load_function = _load_function_from_settings
        load_object = _load_object_from_settings
        kwds = {}
        kwds["find_groups"] = load_function("find_groups", settings)
        kwds["master_secret"] = settings.pop("master_secret", None)
        kwds["nonce_cache"] = load_object("nonce_cache", settings)
        kwds["decode_mac_id"] = load_function("decode_mac_id", settings)
        kwds["encode_mac_id"] = load_function("encode_mac_id", settings)
        return kwds

    def authenticated_userid(self, request):
        """Get the authenticated userid for the given request.

        This method extracts the claimed userid from the request, checks
        the request signature, and calls the groupfinder callback to check
        the validity of the claimed identity.
        """
        userid, key = self._get_credentials(request)
        if userid is None:
            return None
        self._check_signature(request, key)
        if self.find_groups(userid, request) is None:
            return None
        return userid

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for the given request.

        This method extracts the claimed userid from the request without
        checking its authenticity.  This means that the request signature
        is *not* checked when you call this method.  The groupfinder
        callback is also not called.
        """
        userid, _ = self._get_credentials(request)
        return userid

    def effective_principals(self, request):
        """Get the list of effective principals for the given request.

        This method combines the authenticated userid from the request with
        with the list of groups returned by the groupfinder callback, if any.
        """
        principals = [Everyone]
        userid, key = self._get_credentials(request)
        if userid is None:
            return principals
        self._check_signature(request, key)
        groups = self.find_groups(userid, request)
        if groups is None:
            return principals
        principals.insert(0, userid)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Get headers to remember to given principal identity.

        This is a no-op for this plugin; the client is supposed to remember
        its MAC credentials and use them for all requests.
        """
        return []

    def forget(self, request):
        """Get headers to forget the identity in the given request.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.
        """
        return [("WWW-Authenticate", "MAC")]

    def challenge(self, request, content="Unauthorized"):
        """Challenge the user for credentials.

        This method returns a 401 response using the WWW-Authenticate field
        as constructed by forget().  You might like to use it as pyramid's
        "forbidden view" when using this auth policy.
        """
        return HTTPUnauthorized(content, headers=self.forget(request))

    def find_groups(self, userid, request):
        """Find the list of groups for the given userid.

        This method provides a default implementation of the "groupfinder
        callback" used by many pyramid authn policies to look up additional
        user data.  It can be overridden by passing a callable into the
        MACAuthenticationPolicy constructor.

        The default implementation returns an empty list.
        """
        return []

    def decode_mac_id(self, request, tokenid):
        """Decode a MACAuth token id into its userid and MAC secret key.

        This method decodes the given MAC token id to give the corresponding
        userid and MAC secret key.  It is a simple default implementation using
        the tokenlib library, and can be overridden by passing a callable into
        the MACAuthenticationPolicy constructor.

        If the MAC token id is invalid then ValueError will be raised.
        """
        secret = tokenlib.get_token_secret(tokenid, secret=self.master_secret)
        data = tokenlib.parse_token(tokenid, secret=self.master_secret)
        userid = None
        for key in ("username", "userid", "uid", "email"):
            userid = data.get(key)
            if userid is not None:
                break
        else:
            msg = "MAC id contains no userid"
            raise self.challenge(request, msg)
        return userid, secret

    def encode_mac_id(self, request, userid=None, **data):
        """Encode the given userid into a MACAuth token id and secret key.

        This method is essentially the reverse of decode_mac_id.  Given
        a userid, it returns a MACAuth id and corresponding secret key.
        It is not needed for consuming authentication tokens, but is very
        useful when building them for testing purposes.
        """
        if userid is not None:
            data["userid"] = userid
        tokenid = tokenlib.make_token(data, secret=self.master_secret)
        secret = tokenlib.get_token_secret(tokenid, secret=self.master_secret)
        return tokenid, secret

    def _get_params(self, request):
        """Get the MACAuth parameters from the given request.

        This method parses the Authorization header to get the MAC auth
        parameters.  If they seem sensible, we cache them in the request
        to avoid reparsing and return them as a dict.

        If the request contains no MACAuth credentials, None is returned.
        """
        try:
            return request.environ["macauth.params"]
        except KeyError:
            params = macauthlib.utils.parse_authz_header(request, None)
            if params is not None:
                if params.get("scheme").upper() != "MAC":
                    params = None
            request.environ["macauth.params"] = params
            return params

    def _get_credentials(self, request):
        """Extract the MACAuth userid and secret key from the request.

        This method extracts and returns the claimed userid from the MACAuth
        data in the request, along with the corresonding request signing
        key.  It does *not* check the signature on the request.

        If there are no MACAuth credentials in the request then (None, None)
        is returned.  If the MACAuth token id is invalid then HTTPUnauthorized
        will be raised.
        """
        params = self._get_params(request)
        if params is None:
            return None, None
        # Extract  the claimed MAC id token.
        tokenid = macauthlib.get_id(request, params=params)
        if tokenid is None:
            return None, None
        # Parse the MAC id into its userid and MAC key.
        try:
            userid, key = self.decode_mac_id(request, tokenid)
        except ValueError:
            msg = "invalid MAC id: %s" % (tokenid,)
            raise self.challenge(request, msg)
        return userid, key

    def _check_signature(self, request, key):
        """Check the MACAuth signaure on the request.

        This method checks the MAC signature on the request against the
        supplied signing key.  If missing or invalid then HTTPUnauthorized
        is raised.
        """
        # See if we've already checked the signature on this request.
        # This is important because pyramid doesn't cache the results
        # of authenticating the request, but we mark the nonce as stale
        # after the first check.
        if request.environ.get("macauth.signature_is_valid", False):
            return True
        # Grab the (hopefully cached) params from the request.
        params = self._get_params(request)
        if params is None:
            msg = "missing MAC signature"
            raise self.challenge(request, msg)
        # Validate the signature with the given key.
        sig_valid = macauthlib.check_signature(request, key, params=params,
                                               nonces=self.nonce_cache)
        if not sig_valid:
            msg = "invalid MAC signature"
            raise self.challenge(request, msg)
        # Mark this request as having a valid signature.
        request.environ["macauth.signature_is_valid"] = True
        return True


def _load_function_from_settings(name, settings):
    """Load a plugin argument as a function created from the given settings.

    This function is a helper to load and possibly curry a callable argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name] and checks that it is a callable.  It then looks for args
    of the form settings[name_*] and curries them into the function as extra
    keyword argument before returning.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    func = DottedNameResolver(None).resolve(dotted_name)
    # Check that it's a callable.
    if not callable(func):
        raise ValueError("Argument %r must be callable" % (name,))
    # Curry in any keyword arguments.
    func_kwds = {}
    prefix = name + "_"
    for key in settings.keys():
        if key.startswith(prefix):
            func_kwds[key[len(prefix):]] = settings.pop(key)
    # Return the original function if not currying anything.
    # This is both more efficent and better for unit testing.
    if func_kwds:
        func = functools.partial(func, **func_kwds)
    return func


def _load_object_from_settings(name, settings):
    """Load a plugin argument as an object created from the given settings.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name].  If this is a callable, it looks for arguments of the
    form settings[name_*] and calls it with them to instanciate an object.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    obj = DottedNameResolver(None).resolve(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name + "_"
    for key in settings.keys():
        if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = settings.pop(key)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj


def includeme(config):
    """Install MACAuthenticationPolicy into the provided configurator.

    This function provides an easy way to install MAC Access Authentication
    into your pyramid application.  Loads a MACAuthenticationPolicy from the
    deployment settings and installes it into the configurator.
    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set before adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)

    # Build a MACAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = MACAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)

    # Set the forbidden view to use the challenge() method on the policy.
    config.add_forbidden_view(authn_policy.challenge)
