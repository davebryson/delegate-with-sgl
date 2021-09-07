"""
This is an experiment to explore what's needed to use Verifiable Credentials
for delegation.  
"""
from provenance.helpers import Credential, Presentation
from typing import List, Tuple, List
from sgl.principal import Principal
from sgl.api import satisfies
from sgl.rule import Rule


def extract_provenance_chain(credential: Credential) -> List[Credential]:
    """
    Extract the chain into an ordered list of credentials.
    Root credential will be at the start of the returned list
    """

    def decode(credential: Credential, acc: List[Credential]):
        if credential.provenance:
            next = credential.provenance
            acc.append(next)
            decode(next, acc)

    accumlator = [credential]
    decode(credential, accumlator)
    accumlator.reverse()
    return accumlator


def validate_chain(credential: Credential) -> Tuple[bool, Principal]:
    """
    1. Check the root is self-issued
    2. Check the parent and child are linked via provenance
    3. Check the childs rule is a subset of parents
    4. Check child rules are satisifed

    A validated chain only returns a single principal, which
    is the subject of the original credential requested for validation

    What this doesn't do (but should):
    - verify signatures
    - check for revocation status of a credential in the chain
    They were purposefully left out to keep the experiment simple
    """

    # original prinicpal
    ogp = credential.subject.into_principal()

    # We'll always have a list of at least 1 credential
    chain = extract_provenance_chain(credential)

    # start at root: special case of self-issued
    root = chain[0]
    assert root.is_self_signed()
    assert not root.provenance

    rule = root.subject.permission
    principal = root.subject.into_principal()
    assert satisfies(principal, rule)

    if len(chain) == 1:
        return (True, ogp)

    for pindex, child in enumerate(chain[1 : len(chain)]):
        parent = chain[pindex]
        assert parent.subject.id == child.id

        # Check there's no amplification of privilidges
        pg = set(parent.subject.permission.privs)
        cg = set(child.subject.permission.privs)
        assert cg.issubset(pg)

        rule = child.subject.permission
        principal = child.subject.into_principal()
        assert satisfies(principal, rule)

    return (True, ogp)


def verified(presentation: Presentation, rule: Rule) -> bool:
    """
    Validate each chain for each credential in the presentation
    and apply every prinicpal to the associated rules
    """
    principals = []
    for c in presentation.credentials:
        try:
            ok, principal = validate_chain(c)
            assert ok
            principals.append(principal)
        except:
            return False
    return satisfies(principals, rule)
