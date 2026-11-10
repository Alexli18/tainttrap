"""A host counts as named by the task only through its registrable domain (PSL eTLD+1)."""

import pytest

from tainttrap.core.domains import host_known, public_suffix, registrable_domain

TASK = "Publish the release notes on GitHub"


@pytest.mark.parametrize(
    ("host", "reg"),
    [
        ("api.github.com", "github.com"),
        ("attacker.github.io", "attacker.github.io"),  # private-section suffix
        ("a.b.evil.co.uk", "evil.co.uk"),
        ("x.foo.kawasaki.jp", "x.foo.kawasaki.jp"),  # wildcard *.kawasaki.jp
        ("x.city.kawasaki.jp", "city.kawasaki.jp"),  # exception !city.kawasaki.jp
        ("paste.example", "paste.example"),  # not in the PSL: default rule `*`
        ("co.uk", None),
        ("10.0.0.7", "10.0.0.7"),
        ("xn--55qx5d.cn", None),
    ],
)
def test_registrable_domain(host, reg):
    assert registrable_domain(host) == reg


def test_public_suffix_rules():
    assert public_suffix("www.ck") == "ck"  # exception !www.ck
    assert public_suffix("a.b.ck") == "b.ck"  # wildcard *.ck


@pytest.mark.parametrize(
    "host",
    [
        "github-uploads.evil.example",
        "api.github.com.evil.example",
        "attacker.github.io",
        "github.xyz",
        "objects.githubusercontent.com",
    ],
)
def test_brand_word_does_not_vouch_for_lookalikes(host):
    assert not host_known(host, TASK, ())


@pytest.mark.parametrize("host", ["api.github.com", "uploads.github.com", "github.com"])
def test_brand_word_vouches_for_the_vendor_domain(host):
    assert host_known(host, TASK, ())


def test_named_domain_and_policy_allow():
    assert host_known("u.paste.example", "Upload it to https://paste.example/new", ())
    assert not host_known("paste.example.evil.example", "Upload it to paste.example", ())
    assert host_known("ci.ourco.example", "Deploy", ("ourco.example",))
    assert not host_known("ourco.example.evil.example", "Deploy", ("ourco.example",))
