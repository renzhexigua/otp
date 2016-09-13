[![Build Status](https://travis-ci.org/renzhexigua/otp.svg?branch=master)](https://travis-ci.org/renzhexigua/otp)

# One-Time-Password
--------

**`otp`** is implementation of the HOTP ([RFC 4226](https://tools.ietf.org/html/rfc4226)) and TOTP ([RFC 6238](https://tools.ietf.org/html/rfc6238)) algorithms as defined by OATH.

## Features

- [x] Support standard implementation as defined in RFC 4226 and RFC 6238.
- [x] Customizable params, i.e., `token_length`, `digest_algorithm`, `look-ahead size`, `time_step`.
- [x] Reject the second attempt of the OTP after the successful validation has
   been issued for the first OTP.
- [ ] Resynchronization 

From [wikipedia](./https://en.wikipedia.org/wiki/One-time_password)
>A one-time password (OTP) is a password that is valid for only one login session or transaction, on a computer system or other digital device. OTPs avoid a number of shortcomings that are associated with traditional (static) password-based authentication; a number of implementations also incorporate two factor authentication by ensuring that the one-time password requires access to something a person has (such as a small keyring fob device with the OTP calculator built into it, or a smartcard or specific cellphone) as well as something a person knows (such as a PIN).

## Usage

#### HOTP - An HMAC-Based One-Time Password Algorithm

* Code generation

```python
>>> otp_prover = otp.OTPAuth('12345678901234567890')  # counter is 0 by default
>>> otp_prover.hotp()  # counter is 0
'755224'
>>> otp_prover.hotp()  # counter is 1
'287082'
```

* Validation

```python
>>> otp_server = otp.Verifier('12345678901234567890')  # HOTP validator(server) uses the same secret
>>> otp_server.is_valid_hotp('755224')
True
>>> otp_server.is_valid_hotp('287082')
True
>>> otp_server.is_valid_hotp('755224')  # The verifier MUST NOT accept the second attempt of the OTP
   										#  after the successful validation has been issued for the 
   										# first OTP, which ensures one-time only use of an OTP.
False
>>> otp_server.is_valid_hotp('287082')  # the same as above
False
```

#### TOTP: Time-Based One-Time Password Algorithm

* Code generation

```python
>>> otp_prover = otp.OTPAuth('12345678901234567890')
>>> otp_prover.totp(59)  # specific timestamp(current time by default)
'287082'
>>> otp_prover.totp(1111111109)
'081804'
>>> 
```

* Validation

```python
>>> otp_server = otp.Verifier('12345678901234567890')  # TOTP validator(server) uses the same secret
>>> otp_server.is_valid_totp('287082')  # current time by default
False
>>> otp_server.is_valid_totp('287082', 59)  # specific timestamp:59s
True
>>> otp_server.is_valid_totp('081804', 1111111109)  # 1111111109s
True
>>> otp_server.is_valid_totp('287082', 59)  # ensure one-time only use of an OTP
False
>>> otp_server.is_valid_totp('081804', 1111111109)
False
>>> 
```

#### API

* class::**OTPAuth(sec, factor=0, &#42;&#42;kargs)**

	* `sec`: a secret token for the authentication
	* `factor`: counter value, the moving factor (0 by default)
	* `kargs`:
		* digestmod: underlying hash algorithm (sha1 by default)
		* token_length: length of output token (6 by default)
		* interval: time steps in seconds (30s by default)

* func:**hotp()** -- classmethod 

	generate HOTP code via inner moving_factor.

* func:**totp(timestamp=None)** -- classmethod

	generate TOTP code via timestamp.

---

* class::**Verifier(&#42;args, &#42;&#42;kargs)** -- Inherited from OTPAuth
	Additional params:
	* `delay_window`: OTP transmission delay window for validation



* func:**is_valid_hotp(recv_code)** -- classmethod

	verify the receving hotp-code is legal or not.

	* `recv_code`: received authenticator by server

* func:**is_valid_totp(recv_code, timestamp=None)** -- classmethod

	verify the receving totp-code is legal or not.

	* `recv_code`: received authenticator by server
	* `timestamp`: checking point used by server-end

---

* Utility func:**generate_otp(secret, msg, digestmod='sha1', token_length=6)**

	generate an OTP value with the given set of parameters

	* `secret`: secret key for the hmac object
	* `msg`: initial input for the hash
	* `digestmod`: a hashlib constructor or hash name suitable for hashlib.new(). Defaults to hashlib.sha1
	* `token_length`: length of token(6 by default)

For details, please refer to [otp/otp.py](./otp/otp.py)

## License

**MIT**

All code is open source and dual licensed under MIT. Check the individual licenses for more information.