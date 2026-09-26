import pytest
from cryptography.exceptions import InvalidTag

from pcbu import crypto


def test_roundtrip():
    data = b'{"hello": "world"}'
    encrypted = crypto.encrypt_aes(data, "secret")
    assert encrypted != data
    assert crypto.decrypt_aes(encrypted, "secret") == data


def test_encryption_is_salted():
    assert crypto.encrypt_aes(b"data", "secret") != crypto.encrypt_aes(
        b"data", "secret"
    )


def test_wrong_key():
    encrypted = crypto.encrypt_aes(b"data", "secret")
    with pytest.raises(InvalidTag):
        crypto.decrypt_aes(encrypted, "other")


@pytest.mark.parametrize(
    "offset", [-crypto.TIMESTAMP_TIMEOUT - 1000, crypto.TIMESTAMP_TIMEOUT + 1000]
)
def test_expired_timestamp(monkeypatch, offset):
    now = crypto.current_time_millis()
    monkeypatch.setattr(crypto, "current_time_millis", lambda: now + offset)
    encrypted = crypto.encrypt_aes(b"data", "secret")
    monkeypatch.setattr(crypto, "current_time_millis", lambda: now)
    with pytest.raises(Exception, match="Invalid timestamp"):
        crypto.decrypt_aes(encrypted, "secret")
