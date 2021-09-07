from revoke import RevocationList


def test_set_check():
    nl = RevocationList()
    assert 16 * 1024 * 8 == nl.size()

    assert not nl.is_revoked(54)
    nl.revoke(54)
    assert nl.is_revoked(54)

    assert not nl.is_revoked(10320)
    nl.revoke(10320)
    assert nl.is_revoked(10320)
    assert nl.is_revoked(54)


def test_lifecycle():
    nl = RevocationList()
    revoke_list = [2, 131000, 57]

    for i in revoke_list:
        assert not nl.is_revoked(i)

    for i in revoke_list:
        nl.revoke(i)

    for i in revoke_list:
        assert nl.is_revoked(i)

    encoded = nl.encode()

    back = RevocationList.decode(encoded)

    for i in revoke_list:
        assert back.is_revoked(i)

    assert not back.is_revoked(1)
