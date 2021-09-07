"""
Tests to show the use of the SGL code base
"""
from sgl.api import satisfies
from sgl.principal import Principal


def test_delegate():
    rule = {
        "grant": ["backstage"],
        "when": {"all": [{"roles": "press", "n": 2}, {"roles": "stagehand"}]},
    }

    assert satisfies(
        [
            Principal(id="alex", roles=["press"]),
            Principal(id="carol", roles=["press"]),
            Principal(id="bob", roles=["stagehand"]),
        ],
        rule,
    )

    assert not satisfies(
        [
            Principal(id="alex", roles=["press"]),
            Principal(id="bob", roles=["stagehand"]),
        ],
        rule,
    )


def test_grants():
    my_rule = {"grant": ["backstage"], "when": {"roles": "press"}}
    bad = {"id": "Alex", "roles": ["ticket-holder"]}
    good = {"id": "Sofia", "roles": ["ticket-holder", "press"]}

    assert satisfies(good, my_rule)
    assert not satisfies(bad, my_rule)


def test_complex():
    my_rule = {
        "grant": ["backstage"],
        "when": {
            "any": [{"roles": "press", "n": 2}, {"roles": "stagehand", "n": 2}]
        },
    }

    a = [
        Principal(id="alex", roles=["press"]),
        Principal(id="carol", roles=["press"]),
        Principal(id="bob", roles=["stagehand"]),
    ]

    assert satisfies(a, my_rule)


def test_crazy_roles():
    rule = {
        "grant": ["vote"],
        "when": {
            "all": [{"n": 2, "roles": "board"}, {"n": 1, "roles": "investor"}]
        },
    }
    a = [
        Principal(id="tim", roles=["investor", "board"]),
        Principal(id="bob", roles=["investor", "board"]),
        Principal(id="alice", roles=["board"]),
    ]

    assert satisfies(a, rule)
