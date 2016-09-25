#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-

import hmac as _hmac
import time as _time
import struct as _struct
import hashlib as _hashlib
import warnings as _warnings
from _operator import _compare_digest
from functools import wraps as _wraps

_warnings.simplefilter('always', UserWarning)


class OTPAuth():
    """One-Time-Password Authentication.

    **kargs:
        digestmod: A module supporting PEP 247.  *OR*
                   A hashlib constructor returning a new hash object. *OR*
                   A hash name suitable for hashlib.new().
                   Defaults to hashlib.sha1.
        interval:  Time-step in seconds(30 by default).
        token_length:
                   Length of token(6 by default).
    """

    def __init__(self, sec, factor=0, **kargs):
        """Bind a secret.

        secret: A secret token for the authentication.
        factor: Counter value, the moving factor.
        """
        if self._check_secret_constraint(sec):
            self._secret = sec.replace(' ', '')
        self.moving_factor = factor
        self.digestmod = kargs.get('digestmod', _hashlib.sha1)
        self.token_length = kargs.get('token_length', 6)
        self.time_interval = kargs.get('interval', 30)

    def _incrby(func):
        """Decorator: implement auto-increment.
        """
        @_wraps(func)
        def _warpper(*args, **kargs):
            ret = func(*args, **kargs)
            args[0].moving_factor += 1
            return ret
        return _warpper

    @_incrby
    def hotp(self):
        """Generate HOTP code.
        """
        return generate_otp(
            self._secret,
            self.moving_factor,  # event-counter based
            self.digestmod,
            self.token_length
            )

    def totp(self, timestamp=None):
        """Generate TOTP code.

        timestamp: Specific Unix-time.
        """
        T0 = 0
        # https://tools.ietf.org/html/rfc6238
        if not timestamp:
            timestamp = _time.time()
        time_step = int(timestamp - T0) // self.time_interval
        return generate_otp(
            self._secret,
            time_step,  # time based
            self.digestmod,
            self.token_length
            )

    @staticmethod
    def _check_secret_constraint(sec):
        sec = sec.replace(' ', '')
        if len(sec) < 16:
            _warnings.warn(
                '[Warning] The length of the secret' +
                ' SHOULD be at least 128 bits!'
            )
        return True


class Verifier(OTPAuth):
    """Validation system.

    Inherited from OTPAuth.
    """

    def __init__(self, *args, **kargs):
        OTPAuth.__init__(self, *args, **kargs)
        self.delay_window = kargs.get('delay_window', 1)
        self.lookahead_size = 16
        self.outdated_token = [''] * (self.lookahead_size + 1)
        # self.rsync_offset = 0
        # self.max_fail = 3

    def is_valid_hotp(self, recv_code):
        """ Verify the receving hotp-code is legal or not.

        recv_code: Received authenticator by server.
        """
        if recv_code in self.outdated_token:
            return False

        if _compare_digest(self.hotp(), recv_code):
            self.outdated_token = self.outdated_token[-self.lookahead_size:]
            self.outdated_token.append(recv_code)
            return True
        else:
            # Reset to previous value
            _factor = self.moving_factor - 1
            for factor_offset in range(0, self.lookahead_size):
                if _compare_digest(self.hotp(), recv_code):
                    # self.rsync_offset = factor_offset + 1
                    self.moving_factor = _factor + 1
                    self.outdated_token = \
                        self.outdated_token[-self.lookahead_size:]
                    self.outdated_token.append(recv_code)
                    return True
            self.moving_factor = _factor
            return False

    def is_valid_totp(self, recv_code, timestamp=None):
        """ Verify the receving totp-code is legal or not.

        recv_code: Received authenticator by server.
        timestamp: Checking point used by server-end(current time by default).
        By default, we assume the time that the OTP arrives at the receiving
        system is always larger than prover.
        """
        if recv_code in self.outdated_token:
            return False

        if not timestamp:
            timestamp = int(_time.time())
        cur_time = timestamp
        check_code = self.totp(cur_time)
        if _compare_digest(check_code, recv_code):
            self.outdated_token = self.outdated_token[-self.delay_window:]
            self.outdated_token.append(recv_code)
            return True
        # Only check the past timestamps within the transmission delay.
        for t in range(-self.delay_window, 0):
            if _compare_digest(
                    self.totp(cur_time + self.time_interval * t), recv_code):
                self.outdated_token = self.outdated_token[-self.delay_window:]
                self.outdated_token.append(recv_code)
                return True
        return False


def generate_otp(secret, msg, digestmod='sha1', token_length=6):
    """This method generates an OTP value with the given set of parameters.

    secret:    Secret key for the hmac object.
    msg:       Initial input for the hash.
    digestmod: A module supporting PEP 247.  *OR*
               A hashlib constructor returning a new hash object. *OR*
               A hash name suitable for hashlib.new().
               Defaults to hashlib.sha1.
    token_length:
               Length of token(6 by default).
    """
    # Construct a supported parameter of hash type
    if callable(digestmod):
        digest_cons = digestmod
    elif isinstance(digestmod, str):
        digest_cons = lambda d=b'': _hashlib.new(digestmod, d)
    else:
        digest_cons = lambda d=b'': digestmod.new(d)

    # https://tools.ietf.org/html/rfc4226
    msg = _struct.pack('>q', msg)
    digest = _hmac.new(secret.encode(), msg, digest_cons).digest()
    pos = digest[-1] & 0xf
    base = _struct.unpack('>i', digest[pos:pos + 4])[0] & 0x7fffffff
    token = base % (10 ** token_length)

    # Transform to fixed string
    return '{{:0{}d}}'.format(token_length).format(token)
