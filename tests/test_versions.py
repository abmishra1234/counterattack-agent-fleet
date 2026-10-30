from packaging.version import Version

from counterstrike.versions import is_affected, parse_spec, tolerant_version


def test_openssl_letter_suffix_is_compared_by_numeric_prefix():
    v, note = tolerant_version("1.1.1w")
    assert v == Version("1.1.1")
    assert note and "suffix ignored" in note


def test_garbage_version_is_unparseable():
    v, note = tolerant_version("latest")
    assert v is None and "unparseable" in note


def test_inclusive_upper_bound():
    spec = parse_spec(">=3.0.0,<=3.0.7")
    assert is_affected(Version("3.0.7"), spec)
    assert not is_affected(Version("3.0.8"), spec)


def test_invalid_specifier_returns_none():
    assert parse_spec("3.0.0 through 3.0.7") is None
