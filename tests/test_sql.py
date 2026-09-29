"""PY011 - SQL built with string concatenation / formatting."""

import pytest

from app.models.finding import Severity


@pytest.mark.parametrize(
    "code",
    [
        # direct building inside execute()
        "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        "cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
        "cursor.execute('DELETE FROM t WHERE id = {}'.format(item_id))",
        "conn.executemany('INSERT INTO t VALUES (' + v + ')', rows)",
        "User.objects.raw('SELECT * FROM auth_user WHERE id = ' + uid)",
        "import pandas as pd\npd.read_sql(f'SELECT * FROM t WHERE a = {a}', conn)",
        "from sqlalchemy import text\nsession.execute(text(f'SELECT * FROM t WHERE a = {a}'))",
    ],
)
def test_direct_sql_building_is_high(find, code):
    [finding] = find(code, "PY011")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-89"
    assert finding.confidence == 0.85


def test_query_built_in_variable_reports_build_line(find):
    code = """
    def get_user(cursor, user_id):
        query = "SELECT * FROM users WHERE id = " + user_id
        cursor.execute(query)
    """
    [finding] = find(code, "PY011")
    assert finding.line == 4
    assert "built on line 3" in finding.message
    assert finding.sink == "cursor.execute()"


def test_query_extended_with_augmented_assignment(find):
    code = """
    def search(cursor, name):
        query = "SELECT * FROM users WHERE 1 = 1"
        query += " AND name = '" + name + "'"
        cursor.execute(query)
    """
    [finding] = find(code, "PY011")
    assert "built on line 4" in finding.message


def test_dynamic_string_without_sql_keywords_on_db_receiver_is_medium(find):
    [finding] = find("cursor.execute('id = ' + value)", "PY011")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence == 0.55


@pytest.mark.parametrize(
    "code",
    [
        # parameterized queries: the correct way
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "cursor.execute('SELECT * FROM users WHERE id = %(id)s', {'id': user_id})",
        # fully static queries
        "cursor.execute('SELECT * FROM users')",
        "cursor.execute('SELECT * ' + 'FROM users')",
        # variable that is static
        "query = 'SELECT * FROM users'\ncursor.execute(query)",
        # overwritten by a safe value before execution
        "query = 'SELECT * FROM t WHERE a = ' + a\nquery = 'SELECT 1'\ncursor.execute(query)",
        # unknown origin (function parameter): not reported without taint tracking
        "def run(cursor, query):\n    cursor.execute(query)",
        # not a database call
        "executor.execute(f'task {job_id}')",
        "print('SELECT * FROM t WHERE id = ' + i)",
    ],
)
def test_safe_sql_is_not_flagged(find, code):
    assert find(code, "PY011") == []


def test_assignment_in_other_function_is_ignored(find):
    code = """
    def build(user_id):
        query = "SELECT * FROM users WHERE id = " + user_id
        return query

    def run(cursor):
        query = "SELECT * FROM users"
        cursor.execute(query)
    """
    assert find(code, "PY011") == []
