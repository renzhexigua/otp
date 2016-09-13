from otp import OTPAuth, Verifier

SECRET = '1234567890123456789012'


def test_generate_hotp_by_default():
    otp_test = OTPAuth(SECRET)
    assert '446925' == otp_test.hotp()
    assert '104590' == otp_test.hotp()


def test_generate_hotp_with_specific_token_length():
    otp_test = OTPAuth(SECRET, token_length=8)
    assert 8 == otp_test.token_length
    assert '28446925' == otp_test.hotp()
    assert '39104590' == otp_test.hotp()


def test_generate_hotp_with_specific_counter():
    otp_test = OTPAuth(SECRET, 100)
    assert 100 == otp_test.moving_factor
    assert '002109' == otp_test.hotp()
    assert '096748' == otp_test.hotp()
    assert 102 == otp_test.moving_factor


def test_generate_hotp_with_specific_hash():
    otp_test = OTPAuth(SECRET, digestmod='sha1')
    assert '446925' == otp_test.hotp()
    otp_test.digestmod = 'sha256'
    assert '889366' == otp_test.hotp()
    otp_test.digestmod = 'sha512'
    assert '479853' == otp_test.hotp()

    import hashlib as _hashlib
    otp_test = OTPAuth(SECRET, digestmod=_hashlib.sha512)
    assert '167742' == otp_test.hotp()
    otp_test.digestmod = _hashlib.sha256
    assert '889366' == otp_test.hotp()
    otp_test.digestmod = _hashlib.sha1
    assert '267299' == otp_test.hotp()


SECRET2 = '12345678901234567890'


def test_generate_totp_default_with_59s():
    otp_test = OTPAuth(SECRET2)
    assert '287082' == otp_test.totp(59)


def test_generate_totp_default_with_1111111109s():
    otp_test = OTPAuth(SECRET2)
    assert '081804' == otp_test.totp(1111111109)


def test_generate_totp_default_with_1234567890s():
    otp_test = OTPAuth(SECRET2)
    assert '005924' == otp_test.totp(1234567890)


def test_generate_totp_default_with_2000000000s():
    otp_test = OTPAuth(SECRET2)
    assert '279037' == otp_test.totp(2000000000)


def test_generate_totp_default_with_20000000000s():
    otp_test = OTPAuth(SECRET2)
    assert '353130' == otp_test.totp(20000000000)


def test_generate_totp_with_sha256():
    SECRET256 = '12345678901234567890123456789012'
    otp_test = OTPAuth(SECRET256, digestmod='sha256')
    assert '119246' == otp_test.totp(59)
    assert '084774' == otp_test.totp(1111111109)
    assert '062674' == otp_test.totp(1111111111)
    assert '819424' == otp_test.totp(1234567890)
    assert '698825' == otp_test.totp(2000000000)
    assert '737706' == otp_test.totp(20000000000)


def test_generate_totp_with_sha512():
    SECRET512 = (
        '12345678901234567890'
        '12345678901234567890'
        '12345678901234567890'
        '1234'
        )
    otp_test = OTPAuth(SECRET512, digestmod='sha512')
    assert '693936' == otp_test.totp(59)
    assert '091201' == otp_test.totp(1111111109)
    assert '943326' == otp_test.totp(1111111111)
    assert '441116' == otp_test.totp(1234567890)
    assert '618901' == otp_test.totp(2000000000)
    assert '863826' == otp_test.totp(20000000000)


def test_generate_totp_with_specific_interval_60s():
    otp_test = OTPAuth(SECRET2, interval=60)
    assert '755224' == otp_test.totp(59)
    assert '287082' == otp_test.totp(60)
    assert '359152' == otp_test.totp(120)


def test_valid_hotp_by_default_in_windows_16():
    otp_prover = OTPAuth(SECRET)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_hotp(otp_prover.hotp()) is True

    otp_prover = OTPAuth(SECRET, 16)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_hotp(otp_prover.hotp()) is True


def test_valid_hotp_by_default_out_of_windows_16():
    otp_prover = OTPAuth(SECRET, 17)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_hotp(otp_prover.hotp()) is False


def test_valid_hotp_used_code():
    otp_prover = OTPAuth(SECRET)
    otp_server = Verifier(SECRET)
    code0 = otp_prover.hotp()
    code1 = otp_prover.hotp()
    code2 = otp_prover.hotp()
    code3 = otp_prover.hotp()
    code4 = otp_prover.hotp()
    code5 = otp_prover.hotp()
    otp_server.is_valid_hotp(code0)
    otp_server.is_valid_hotp(code1)
    otp_server.is_valid_hotp(code2)
    otp_server.is_valid_hotp(code3)
    otp_server.is_valid_hotp(code4)

    assert otp_server.is_valid_hotp(code0) is False
    assert otp_server.is_valid_hotp(code1) is False
    assert otp_server.is_valid_hotp(code2) is False
    assert otp_server.is_valid_hotp(code3) is False
    assert otp_server.is_valid_hotp(code4) is False
    assert otp_server.is_valid_hotp(code5) is True


def test_valid_totp_by_default_in_windows_1():
    otp_prover = OTPAuth(SECRET)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_totp(otp_prover.totp(59), 89) is True
    assert otp_server.is_valid_totp(otp_prover.totp()) is True


def test_valid_totp_by_default_out_of_windows_1():
    otp_prover = OTPAuth(SECRET)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_totp(otp_prover.totp(59), 90) is False


def test_valid_totp_used_code():
    otp_prover = OTPAuth(SECRET)
    otp_server = Verifier(SECRET)
    assert otp_server.is_valid_totp(otp_prover.totp(59), 89) is True
    assert otp_server.is_valid_totp(otp_prover.totp(59), 89) is False
    assert otp_server.is_valid_totp(otp_prover.totp(59), 69) is False
    assert otp_server.is_valid_totp(otp_prover.totp()) is True
    assert otp_server.is_valid_totp(otp_prover.totp()) is False
