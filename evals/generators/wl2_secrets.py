"""WL2 — Secret-heavy configuration generator.

Synthetic config files, logs, and code snippets containing API keys,
bearer tokens, certificates, and credentials. ~300 samples.
"""

from __future__ import annotations

from ..schema import Annotation, Sample
from .corpus import Corpus


def _track(text: str, value: str, kind: str, annotations: list[Annotation]) -> None:
    start = 0
    while True:
        pos = text.find(value, start)
        if pos == -1:
            break
        annotations.append(Annotation(start=pos, end=pos + len(value), kind=kind, text=value))
        start = pos + len(value)


# --- Templates ---


def _env_file(c: Corpus) -> tuple[str, list[Annotation]]:
    aws_key = c.aws_access_key()
    aws_secret = c.aws_secret_key()
    api_key = c.generic_api_key()
    db_pass = c.password()
    text = (
        f"# .env\n"
        f"AWS_ACCESS_KEY_ID={aws_key}\n"
        f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
        f"API_KEY={api_key}\n"
        f"DATABASE_PASSWORD={db_pass}\n"
        f"NODE_ENV=production\n"
    )
    anns: list[Annotation] = []
    _track(text, aws_key, "aws_access_key", anns)
    _track(text, aws_secret, "aws_secret_key", anns)
    _track(text, api_key, "api_key", anns)
    _track(text, db_pass, "password", anns)
    return text, anns


def _yaml_config(c: Corpus) -> tuple[str, list[Annotation]]:
    api_key = c.generic_api_key()
    hostname = c.hostname()
    db_pass = c.password()
    text = (
        f"database:\n"
        f"  host: {hostname}\n"
        f"  port: 5432\n"
        f"  password: \"{db_pass}\"\n"
        f"api:\n"
        f"  key: \"{api_key}\"\n"
        f"  timeout: 30\n"
    )
    anns: list[Annotation] = []
    _track(text, api_key, "api_key", anns)
    _track(text, hostname, "hostname", anns)
    _track(text, db_pass, "password", anns)
    return text, anns


def _docker_compose(c: Corpus) -> tuple[str, list[Annotation]]:
    db_pass = c.password()
    api_key = c.generic_api_key()
    text = (
        f"version: '3.8'\n"
        f"services:\n"
        f"  db:\n"
        f"    image: postgres:15\n"
        f"    environment:\n"
        f"      POSTGRES_PASSWORD: {db_pass}\n"
        f"  api:\n"
        f"    image: myapp:latest\n"
        f"    environment:\n"
        f"      API_KEY: {api_key}\n"
    )
    anns: list[Annotation] = []
    _track(text, db_pass, "password", anns)
    _track(text, api_key, "api_key", anns)
    return text, anns


def _python_config(c: Corpus) -> tuple[str, list[Annotation]]:
    api_key = c.generic_api_key()
    token = c.bearer_token()
    text = (
        f'import os\n\n'
        f'API_KEY = "{api_key}"\n'
        f'AUTH_TOKEN = "Bearer {token}"\n'
        f'DEBUG = False\n'
    )
    anns: list[Annotation] = []
    _track(text, api_key, "api_key", anns)
    _track(text, token, "bearer_token", anns)
    return text, anns


def _curl_command(c: Corpus) -> tuple[str, list[Annotation]]:
    token = c.bearer_token()
    hostname = c.hostname()
    text = (
        f"curl -X POST https://{hostname}/api/v1/data \\\n"
        f"  -H 'Authorization: Bearer {token}' \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d '{{\"query\": \"SELECT * FROM users\"}}'"
    )
    anns: list[Annotation] = []
    _track(text, token, "bearer_token", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _log_with_credentials(c: Corpus) -> tuple[str, list[Annotation]]:
    email = c.email()
    ip = c.ip_v4()
    token = c.bearer_token()
    text = (
        f"[ERROR] 2026-04-10 09:15:33 auth.middleware: "
        f"Failed login for {email} from {ip}. "
        f"Token presented: Bearer {token}"
    )
    anns: list[Annotation] = []
    _track(text, email, "email", anns)
    _track(text, ip, "ip_address", anns)
    _track(text, token, "bearer_token", anns)
    return text, anns


def _terraform_vars(c: Corpus) -> tuple[str, list[Annotation]]:
    aws_key = c.aws_access_key()
    aws_secret = c.aws_secret_key()
    text = (
        f'variable "aws_access_key" {{\n'
        f'  default = "{aws_key}"\n'
        f'}}\n\n'
        f'variable "aws_secret_key" {{\n'
        f'  default = "{aws_secret}"\n'
        f'}}\n'
    )
    anns: list[Annotation] = []
    _track(text, aws_key, "aws_access_key", anns)
    _track(text, aws_secret, "aws_secret_key", anns)
    return text, anns


def _json_config(c: Corpus) -> tuple[str, list[Annotation]]:
    api_key = c.generic_api_key()
    db_pass = c.password()
    hostname = c.hostname()
    text = (
        f'{{\n'
        f'  "database": {{\n'
        f'    "host": "{hostname}",\n'
        f'    "password": "{db_pass}"\n'
        f'  }},\n'
        f'  "api_key": "{api_key}"\n'
        f'}}'
    )
    anns: list[Annotation] = []
    _track(text, api_key, "api_key", anns)
    _track(text, db_pass, "password", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _ssh_config(c: Corpus) -> tuple[str, list[Annotation]]:
    hostname = c.hostname()
    ip = c.ip_v4()
    text = (
        f"Host production\n"
        f"  HostName {hostname}\n"
        f"  User deploy\n"
        f"  IdentityFile ~/.ssh/prod_rsa\n"
        f"  # IP: {ip}\n"
        f"  # -----BEGIN RSA PRIVATE KEY-----\n"
        f"  # MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn...\n"
        f"  # -----END RSA PRIVATE KEY-----\n"
    )
    anns: list[Annotation] = []
    _track(text, hostname, "hostname", anns)
    _track(text, ip, "ip_address", anns)
    # Track the PEM marker
    pem_marker = "-----BEGIN RSA PRIVATE KEY-----"
    _track(text, pem_marker, "pem_private_key", anns)
    return text, anns


def _github_actions(c: Corpus) -> tuple[str, list[Annotation]]:
    api_key = c.generic_api_key()
    token = c.bearer_token()
    text = (
        f"name: Deploy\n"
        f"on: push\n"
        f"jobs:\n"
        f"  deploy:\n"
        f"    runs-on: ubuntu-latest\n"
        f"    env:\n"
        f"      API_KEY: {api_key}\n"
        f"      DEPLOY_TOKEN: {token}\n"
        f"    steps:\n"
        f"      - uses: actions/checkout@v4\n"
    )
    anns: list[Annotation] = []
    _track(text, api_key, "api_key", anns)
    _track(text, token, "bearer_token", anns)
    return text, anns


def _slack_webhook(c: Corpus) -> tuple[str, list[Annotation]]:
    api_key = c.generic_api_key()
    text = (
        f'SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/{api_key}"\n\n'
        f"def notify(message: str):\n"
        f"    import requests\n"
        f'    requests.post(SLACK_WEBHOOK_URL, json={{"text": message}})\n'
    )
    anns: list[Annotation] = []
    _track(text, api_key, "api_key", anns)
    return text, anns


def _connection_string(c: Corpus) -> tuple[str, list[Annotation]]:
    db_pass = c.password()
    hostname = c.hostname()
    text = (
        f"# Database connection\n"
        f"DATABASE_URL=postgresql://admin:{db_pass}@{hostname}:5432/production\n"
        f"REDIS_URL=redis://{hostname}:6379/0\n"
    )
    anns: list[Annotation] = []
    _track(text, db_pass, "password", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _jwt_debug(c: Corpus) -> tuple[str, list[Annotation]]:
    token = c.bearer_token()
    email = c.email()
    text = (
        f"Debug: JWT token for {email}:\n"
        f"Authorization: Bearer {token}\n"
        f"Expires: 2026-04-15T00:00:00Z\n"
    )
    anns: list[Annotation] = []
    _track(text, token, "bearer_token", anns)
    _track(text, email, "email", anns)
    return text, anns


def _aws_cli_output(c: Corpus) -> tuple[str, list[Annotation]]:
    aws_key = c.aws_access_key()
    aws_secret = c.aws_secret_key()
    text = (
        f"$ aws configure list\n"
        f"      Name                    Value             Type    Location\n"
        f"      ----                    -----             ----    --------\n"
        f"   profile                <not set>             None    None\n"
        f"access_key     {aws_key} shared-credentials-file\n"
        f"secret_key     {aws_secret} shared-credentials-file\n"
        f"    region                us-east-1      config-file    ~/.aws/config\n"
    )
    anns: list[Annotation] = []
    _track(text, aws_key, "aws_access_key", anns)
    _track(text, aws_secret, "aws_secret_key", anns)
    return text, anns


TEMPLATES = [
    _env_file,
    _yaml_config,
    _docker_compose,
    _python_config,
    _curl_command,
    _log_with_credentials,
    _terraform_vars,
    _json_config,
    _ssh_config,
    _github_actions,
    _slack_webhook,
    _connection_string,
    _jwt_debug,
    _aws_cli_output,
]


def generate_wl2(n: int = 300, seed: int = 43) -> list[Sample]:
    """Generate n secret-heavy configuration samples."""
    corpus = Corpus(seed=seed)
    samples: list[Sample] = []
    for i in range(n):
        template = TEMPLATES[i % len(TEMPLATES)]
        text, anns = template(corpus)
        sample = Sample(id=f"wl2_{i:04d}", text=text, annotations=anns)
        sample.validate()
        samples.append(sample)
    return samples
