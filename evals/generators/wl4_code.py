"""WL4 — Proprietary code generator.

Code containing internal function names, variable names, database
schemas, and comments referencing internal projects. ~300 samples.
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


def _python_internal_api(c: Corpus) -> tuple[str, list[Annotation]]:
    func = c.internal_function()
    project = c.project_name()
    company = c.company()
    db = c.database_name()
    text = (
        f"# {project} - {company} internal\n"
        f"def {func}(record_id: int) -> dict:\n"
        f'    """Process record from {db}."""\n'
        f"    conn = get_connection('{db}')\n"
        f"    row = conn.execute(\n"
        f"        'SELECT * FROM {c.table_name()} WHERE id = ?',\n"
        f"        (record_id,)\n"
        f"    ).fetchone()\n"
        f"    return dict(row)\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    _track(text, func, "internal_function", anns)
    _track(text, db, "database_name", anns)
    return text, anns


def _sql_schema(c: Corpus) -> tuple[str, list[Annotation]]:
    table = c.table_name()
    company = c.company()
    text = (
        f"-- {company} production schema\n"
        f"CREATE TABLE {table} (\n"
        f"    id SERIAL PRIMARY KEY,\n"
        f"    full_name VARCHAR(255) NOT NULL,\n"
        f"    email VARCHAR(255) UNIQUE,\n"
        f"    ssn_encrypted BYTEA,\n"
        f"    salary_band INTEGER,\n"
        f"    manager_id INTEGER REFERENCES employees(id),\n"
        f"    created_at TIMESTAMP DEFAULT NOW()\n"
        f");\n"
    )
    anns: list[Annotation] = []
    _track(text, company, "org_name", anns)
    _track(text, table, "table_name", anns)
    return text, anns


def _api_endpoint(c: Corpus) -> tuple[str, list[Annotation]]:
    project = c.project_name()
    company = c.company()
    hostname = c.hostname()
    api_key = c.generic_api_key()
    text = (
        f"# {project} API client - {company}\n"
        f"import httpx\n\n"
        f'BASE_URL = "https://{hostname}/api/v2"\n'
        f'API_KEY = "{api_key}"\n\n'
        f"async def fetch_metrics():\n"
        f"    async with httpx.AsyncClient() as client:\n"
        f"        resp = await client.get(\n"
        f"            f'{{BASE_URL}}/metrics',\n"
        f"            headers={{'X-API-Key': API_KEY}}\n"
        f"        )\n"
        f"        return resp.json()\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    _track(text, hostname, "hostname", anns)
    _track(text, api_key, "api_key", anns)
    return text, anns


def _migration_script(c: Corpus) -> tuple[str, list[Annotation]]:
    table = c.table_name()
    company = c.company()
    project = c.project_name()
    text = (
        f"-- Migration: {project} ({company})\n"
        f"-- JIRA: PLAT-4821\n\n"
        f"ALTER TABLE {table}\n"
        f"  ADD COLUMN department VARCHAR(100),\n"
        f"  ADD COLUMN cost_center VARCHAR(20),\n"
        f"  ADD COLUMN last_review_date DATE;\n\n"
        f"-- Backfill from HR export\n"
        f"UPDATE {table} SET department = hr.dept\n"
        f"  FROM hr_export hr WHERE {table}.id = hr.emp_id;\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    _track(text, table, "table_name", anns)
    return text, anns


def _go_handler(c: Corpus) -> tuple[str, list[Annotation]]:
    func = c.internal_function()
    project = c.project_name()
    hostname = c.hostname()
    text = (
        f"// {project} internal handler\n"
        f"package main\n\n"
        f"import (\n"
        f'    "net/http"\n'
        f'    "log"\n'
        f")\n\n"
        f"const internalEndpoint = \"https://{hostname}/rpc\"\n\n"
        f"func {func.lstrip('_')}Handler(w http.ResponseWriter, r *http.Request) {{\n"
        f'    log.Printf("processing request from %s", r.RemoteAddr)\n'
        f"    // business logic\n"
        f"    w.WriteHeader(http.StatusOK)\n"
        f"}}\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _dockerfile(c: Corpus) -> tuple[str, list[Annotation]]:
    project = c.project_name()
    company = c.company()
    api_key = c.generic_api_key()
    text = (
        f"# {project} - {company}\n"
        f"FROM python:3.12-slim\n\n"
        f"WORKDIR /app\n"
        f"COPY requirements.txt .\n"
        f"RUN pip install -r requirements.txt\n\n"
        f"# TODO: move to secrets manager\n"
        f"ENV API_KEY={api_key}\n\n"
        f"COPY . .\n"
        f'CMD ["python", "main.py"]\n'
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    _track(text, api_key, "api_key", anns)
    return text, anns


def _test_fixture(c: Corpus) -> tuple[str, list[Annotation]]:
    func = c.internal_function()
    table = c.table_name()
    name = c.full_name()
    email = c.email(name)
    text = (
        f"def test{func}():\n"
        f'    """Regression test for PLAT-3392."""\n'
        f"    record = {{\n"
        f'        "name": "{name}",\n'
        f'        "email": "{email}",\n'
        f'        "table": "{table}",\n'
        f"    }}\n"
        f"    result = {func.lstrip('_')}(record)\n"
        f"    assert result['status'] == 'processed'\n"
    )
    anns: list[Annotation] = []
    _track(text, func, "internal_function", anns)
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    _track(text, table, "table_name", anns)
    return text, anns


def _graphql_schema(c: Corpus) -> tuple[str, list[Annotation]]:
    company = c.company()
    project = c.project_name()
    text = (
        f"# {project} GraphQL schema ({company})\n"
        f"type Employee {{\n"
        f"  id: ID!\n"
        f"  fullName: String!\n"
        f"  email: String!\n"
        f"  department: String\n"
        f"  salaryBand: Int\n"
        f"  manager: Employee\n"
        f"  performanceReviews: [Review!]!\n"
        f"}}\n\n"
        f"type Query {{\n"
        f"  employee(id: ID!): Employee\n"
        f"  employeesByDepartment(dept: String!): [Employee!]!\n"
        f"}}\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    return text, anns


def _celery_task(c: Corpus) -> tuple[str, list[Annotation]]:
    func = c.internal_function()
    project = c.project_name()
    db = c.database_name()
    hostname = c.hostname()
    text = (
        f"# {project} background tasks\n"
        f"from celery import shared_task\n\n"
        f"@shared_task(bind=True, max_retries=3)\n"
        f"def {func.lstrip('_')}(self, batch_id: int):\n"
        f'    """Nightly reconciliation against {db}."""\n'
        f"    conn = connect('{hostname}', db='{db}')\n"
        f"    rows = conn.execute('SELECT * FROM pending_reconciliation')\n"
        f"    for row in rows:\n"
        f"        process(row)\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, func, "internal_function", anns)
    _track(text, db, "database_name", anns)
    _track(text, hostname, "hostname", anns)
    return text, anns


def _readme_internal(c: Corpus) -> tuple[str, list[Annotation]]:
    project = c.project_name()
    company = c.company()
    team = c.team_name()
    name = c.full_name()
    email = c.email(name)
    text = (
        f"# {project}\n\n"
        f"Internal tool for {company}'s {team} team.\n\n"
        f"## Contact\n"
        f"Owner: {name} ({email})\n\n"
        f"## Setup\n"
        f"1. Clone the repo\n"
        f"2. Run `make setup`\n"
        f"3. Copy `.env.example` to `.env` and fill in credentials\n"
    )
    anns: list[Annotation] = []
    _track(text, project, "project_name", anns)
    _track(text, company, "org_name", anns)
    _track(text, name, "person", anns)
    _track(text, email, "email", anns)
    return text, anns


def _error_log(c: Corpus) -> tuple[str, list[Annotation]]:
    hostname = c.hostname()
    ip = c.ip_v4()
    db = c.database_name()
    email = c.email()
    text = (
        f"[2026-04-10 03:14:22] ERROR {hostname} pool={db}: "
        f"connection refused from {ip}\n"
        f"[2026-04-10 03:14:23] ERROR {hostname} auth: "
        f"failed login attempt for {email}\n"
        f"[2026-04-10 03:14:25] WARN {hostname}: "
        f"circuit breaker open for upstream service\n"
    )
    anns: list[Annotation] = []
    _track(text, hostname, "hostname", anns)
    _track(text, ip, "ip_address", anns)
    _track(text, db, "database_name", anns)
    _track(text, email, "email", anns)
    return text, anns


TEMPLATES = [
    _python_internal_api,
    _sql_schema,
    _api_endpoint,
    _migration_script,
    _go_handler,
    _dockerfile,
    _test_fixture,
    _graphql_schema,
    _celery_task,
    _readme_internal,
    _error_log,
]


def generate_wl4(n: int = 300, seed: int = 45) -> list[Sample]:
    """Generate n proprietary code samples."""
    corpus = Corpus(seed=seed)
    samples: list[Sample] = []
    for i in range(n):
        template = TEMPLATES[i % len(TEMPLATES)]
        text, anns = template(corpus)
        sample = Sample(id=f"wl4_{i:04d}", text=text, annotations=anns)
        sample.validate()
        samples.append(sample)
    return samples
