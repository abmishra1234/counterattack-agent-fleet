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


def test_range_unions_and_matched_fix():
    from counterstrike.versions import exclusive_upper_bound, matching_range, parse_ranges

    ranges = parse_ranges(">=2.0,<2.12.2 || >=2.13.0,<2.17.1")
    assert len(ranges) == 2
    assert exclusive_upper_bound(matching_range(Version("2.14.0"), ranges)) == "2.17.1"
    assert matching_range(Version("2.12.5"), ranges) is None
    assert parse_ranges("<1 ||") is None
    assert parse_ranges("<1 || nonsense") is None
    assert exclusive_upper_bound(parse_spec("<=1.4")) is None
