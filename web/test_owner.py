import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import relay

class OwnerLockTests(unittest.IsolatedAsyncioTestCase):
    async def test_owner_is_accepted(self):
        result = SimpleNamespace(subject="12345678")
        with patch.object(relay.GitHubTokenVerifier, "verify_token", AsyncMock(return_value=result)):
            verifier = relay.OwnerOnlyVerifier([12345678], required_scopes=["read:user"])
            self.assertIs(await verifier.verify_token("local-test-token"), result)

    async def test_other_account_is_rejected(self):
        result = SimpleNamespace(subject="999999")
        with patch.object(relay.GitHubTokenVerifier, "verify_token", AsyncMock(return_value=result)):
            verifier = relay.OwnerOnlyVerifier([12345678], required_scopes=["read:user"])
            self.assertIsNone(await verifier.verify_token("local-test-token"))

    async def test_invalid_token_is_rejected(self):
        with patch.object(relay.GitHubTokenVerifier, "verify_token", AsyncMock(return_value=None)):
            verifier = relay.OwnerOnlyVerifier([12345678], required_scopes=["read:user"])
            self.assertIsNone(await verifier.verify_token("local-test-token"))


class ConfigurationTests(unittest.TestCase):
    def config(self):
        return dict(public_url="https://reach.example.test", client_id="dummy",
                    client_secret="dummy-secret", jwt_signing_key="s" * 48,
                    native_token="t" * 32, allowed_github_user_ids=[12345678],
                    native_url="http://127.0.0.1:8765/mcp")

    def test_valid_owner_and_loopback(self):
        self.assertEqual(relay.validate_config(self.config())["allowed_github_user_ids"], [12345678])

    def test_owner_must_be_single_positive_integer(self):
        for ids in ([], [1, 2], [True], ["123"], [0], [-1], None):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                relay.validate_config(dict(self.config(), allowed_github_user_ids=ids))

    def test_native_cannot_leave_loopback(self):
        for url in ("https://remote.example/mcp", "http://192.168.1.2:8765/mcp",
                    "http://127.0.0.1/mcp", "http://127.0.0.1:8765/other",
                    "http://user:password@127.0.0.1:8765/mcp", "http://127.0.0.1:8765/mcp?token=x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                relay.validate_config(dict(self.config(), native_url=url))

    def test_public_must_be_https_origin(self):
        for url in ("http://reach.example.test", "https://reach.example.test/path",
                    "https://user:password@reach.example.test", "https://reach.example.test#fragment"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                relay.validate_config(dict(self.config(), public_url=url))


if __name__ == "__main__":
    unittest.main()
