from tools.versioning import satisfies


def test_less_than():
    assert satisfies("5.3.1", "<5.4")
    assert not satisfies("5.4", "<5.4")
    assert not satisfies("5.4.1", "<5.4")


def test_range():
    assert satisfies("1.1", ">=1.0,<1.2")
    assert not satisfies("1.2", ">=1.0,<1.2")
    assert not satisfies("0.9", ">=1.0,<1.2")


def test_prerelease_sorts_low():
    assert satisfies("2.10.1rc1", "<2.10.1")
    assert not satisfies("2.10.1", "<2.10.1")


def test_empty_version_is_false():
    assert not satisfies("", "<5.4")
