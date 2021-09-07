"""
Provide models used for testing.
Simplified and don't provide all information
"""
from typing import List, Union
from dataclasses import dataclass
from sgl.rule import Rule
from sgl.principal import Principal


@dataclass
class Subject:
    id: str
    role: str
    permission: Rule

    def into_principal(self):
        return Principal(id=self.id, roles=[self.role])


@dataclass
class Credential:
    id: str
    provenance: Union[any, None]
    subject: Subject

    def is_self_signed(self) -> bool:
        return self.id == self.subject.id


@dataclass
class Presentation:
    credentials: List[Credential]


def create_credential(
    issuer: str,
    subject: str,
    role: str,
    trust_framework: dict,
    prov: Union[Credential, None] = None,
) -> dict:
    rule: dict = trust_framework.get(role, None)
    assert rule
    credential = Credential(issuer, prov, Subject(subject, role, rule))
    if not prov:
        assert credential.id == credential.subject.id
        return credential
    else:
        # Ensure the issuer was the subject of parent (chain link)
        assert credential.id == prov.subject.id
        # encode the parent and add to provenance
        credential.provenance = prov
        return credential
