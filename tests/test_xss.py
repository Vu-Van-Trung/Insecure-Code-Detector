"""PY018 - cross-site scripting and server-side template injection."""

import pytest

from app.models.finding import Severity

FLASK = "from flask import Flask, Markup, Response, make_response, render_template_string, request\n"


@pytest.mark.parametrize(
    "code",
    [
        FLASK + "render_template_string(request.args['t'])",
        FLASK + "render_template_string('<h1>' + request.args['n'] + '</h1>')",
        FLASK + "from markupsafe import escape\nrender_template_string(f\"<h1>{escape(request.args['n'])}</h1>\")",
        "import jinja2\njinja2.Template(request.form['tpl'])",
        "env.from_string(request.args['tpl'])",
    ],
)
def test_template_injection_is_critical(find, code):
    """HTML escaping does not stop {{ 7*7 }}: escape() is not accepted for template source."""
    [finding] = find(code, "PY018")
    assert finding.severity is Severity.CRITICAL
    assert finding.cwe == "CWE-1336"


def test_dynamic_template_source_is_high(find):
    code = FLASK + "def page(title):\n    return render_template_string(f'<h1>{title}</h1>')"
    [finding] = find(code, "PY018")
    assert finding.severity is Severity.HIGH
    assert finding.cwe == "CWE-1336"
    assert finding.confidence == 0.75


@pytest.mark.parametrize(
    "code, severity",
    [
        (FLASK + "Markup(request.args['bio'])", Severity.HIGH),
        ("from django.utils.safestring import mark_safe\nmark_safe(request.GET['bio'])", Severity.HIGH),
        (FLASK + "def f(bio):\n    return Markup(bio)", Severity.MEDIUM),
        (FLASK + "make_response('<p>' + request.args['q'] + '</p>')", Severity.HIGH),
        (FLASK + "Response(request.args['q'])", Severity.MEDIUM),
        ("from django.http import HttpResponse\nh = f\"<b>{request.GET['q']}</b>\"\nHttpResponse(h)", Severity.HIGH),
        (FLASK + "def view():\n    n = request.args['n']\n    return f'<p>{n}</p>'", Severity.HIGH),
        (FLASK + "def view():\n    out = '<ul>'\n    for i in request.args.getlist('i'):\n"
                 "        out += f'<li>{i}</li>'\n    return out", Severity.HIGH),
        (FLASK + "app = Flask(__name__)\n@app.route('/')\ndef view():\n    return 'Hi ' + request.args['n']",
         Severity.MEDIUM),
        ("import jinja2\njinja2.Environment(autoescape=False)", Severity.HIGH),
        ("import jinja2\njinja2.Environment(loader=jinja2.FileSystemLoader('t'))", Severity.MEDIUM),
    ],
)
def test_xss_is_reported(find, code, severity):
    [finding] = find(code, "PY018")
    assert finding.severity is severity
    assert finding.cwe == "CWE-79"


@pytest.mark.parametrize(
    "code",
    [
        FLASK + "render_template_string('<h1>{{ n }}</h1>', n=request.args['n'])",
        FLASK + "TPL = '<h1>{{ n }}</h1>'\nrender_template_string(TPL, n=request.args['n'])",
        FLASK + "def page(tpl):\n    return render_template_string(tpl)",  # unknown origin, not built here
        FLASK + "Markup('<b>safe</b>')",
        FLASK + "Markup('<b>{}</b>').format(request.args['n'])",  # Markup.format escapes its arguments
        FLASK + "from markupsafe import escape\nMarkup(escape(request.args['n']))",
        FLASK + "import html\nmake_response('<p>' + html.escape(request.args['q']) + '</p>')",
        FLASK + "from flask import jsonify\nmake_response(jsonify(request.json))",
        FLASK + "Response(request.args['q'], mimetype='text/plain')",
        FLASK + "def name():\n    return request.args['n']",  # helper, not HTML
        FLASK + "def label():\n    return 'Hi ' + request.args['n']",  # not a route handler
        "def ask():\n    n = input()\n    return f'<p>{n}</p>'",  # not web request data
        "import jinja2\njinja2.Environment(autoescape=True)",
        "import jinja2\njinja2.Environment(autoescape=jinja2.select_autoescape())",
        "import jinja2\njinja2.Environment(**options)",
        "env.from_string(TEMPLATE)",
    ],
)
def test_safe_html_is_not_flagged(find, code):
    assert find(code, "PY018") == []
