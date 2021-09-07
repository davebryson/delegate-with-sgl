"""
Complex chains:
[p.[a], p.[b,c], p.[d,e,f]]
"""
import pytest
from sgl.rule import Rule
from provenance.helpers import Presentation, create_credential
from provenance.chain import extract_provenance_chain, validate_chain, verified


"""
permissions: purchase, rent, sell, drive

Roles:
corporate: all
manager: rent, sell, drive
dealer: rent, drive
salesname: sell, when approved by 2 managers and a salesman
customer: drive (must have dealer or above in chain )
"""
AcmeRental = {
    "corporate": Rule(
        ["purchase", "rent", "sell", "drive"],
        {"roles": "corporate"},
    ),
    "manager": Rule(["rent", "sell", "drive"], {"roles": "manager"}),
    "dealer": Rule(["rent", "drive"], {"roles": "dealer"}),
    "salesman": Rule(
        ["sell"], {"all": [{"roles": "manager", "n": 2}, {"roles": "dealer"}]}
    ),
    "customer": Rule(["drive"], {"roles": "customer"}),
}


def test_pieces():
    wheelz = create_credential("acme", "acme", "corporate", AcmeRental, None)
    assert wheelz.id == "acme"
    assert wheelz.provenance == None
    assert wheelz.subject.id == "acme"
    assert wheelz.subject.permission == AcmeRental["corporate"]
    assert wheelz.is_self_signed()

    bob = create_credential("acme", "bob", "dealer", AcmeRental, wheelz)
    assert bob.id == "acme"
    assert bob.subject.id == "bob"
    assert bob.subject.permission == AcmeRental["dealer"]
    assert bob.provenance == wheelz

    chain = extract_provenance_chain(bob)
    root = chain[0]
    assert root.id == "acme"
    assert root.provenance == None
    assert root.subject.id == "acme"
    assert root.subject.permission == AcmeRental["corporate"]
    assert root.is_self_signed()

    bob = chain[1]
    assert bob.id == "acme"
    assert bob.subject.id == "bob"
    assert bob.subject.permission == AcmeRental["dealer"]
    assert bob.provenance == wheelz

    ok, principal = validate_chain(bob)
    assert ok
    assert "bob" == principal.id

    presentation = Presentation([bob])
    assert verified(presentation, AcmeRental["dealer"])
    assert not verified(presentation, AcmeRental["corporate"])


def test_simple_delegation():
    """
    Delegate drive to a customer and test they have the permission
    """
    acme = create_credential("acme", "acme", "corporate", AcmeRental, None)
    bob = create_credential("acme", "bob", "manager", AcmeRental, acme)
    alice = create_credential("bob", "alice", "dealer", AcmeRental, bob)
    mallory = create_credential(
        "alice", "mallory", "customer", AcmeRental, alice
    )

    presentation = Presentation([mallory])

    # Mallory can drive the car
    assert verified(presentation, AcmeRental["customer"])

    # ... but she can't act as a dealer
    assert not verified(presentation, AcmeRental["dealer"])

    # Incorrect chain.  No provenance
    with pytest.raises(AssertionError):
        fail1 = create_credential("acme", "bob", "manager", AcmeRental, None)
    # p1 = Presentation([fail1])
    # assert not verified(p1, AcmeRental["manager"])


def test_aggregate_approval():
    acme = create_credential("acme", "acme", "corporate", AcmeRental, None)
    manager1 = create_credential("acme", "bob", "manager", AcmeRental, acme)
    manager2 = create_credential("acme", "carl", "manager", AcmeRental, acme)
    dealer = create_credential("bob", "alice", "dealer", AcmeRental, manager1)

    assert verified(
        Presentation([dealer, manager1, manager2]), AcmeRental["salesman"]
    )
    assert not verified(
        Presentation([dealer, manager1]), AcmeRental["salesman"]
    )
