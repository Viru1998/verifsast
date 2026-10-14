# CWE-798: Near-miss — template placeholder {{ SECRET_KEY }}
# The value is a Jinja2/Ansible-style template placeholder that is
# rendered by a deployment tool before the file is used.
# Scanners should classify this as a placeholder, not a real secret.

import os
import re


# Near-miss: this is a configuration template, not runtime code.
# At deploy time the CI/CD system renders {{ SECRET_KEY }} to the real value.
SECRET = "{{ SECRET_KEY }}"
DATABASE_URL = "postgresql://{{ DB_USER }}:{{ DB_PASS }}@{{ DB_HOST }}/{{ DB_NAME }}"
API_KEY = "{{ EXTERNAL_API_KEY }}"


TEMPLATE_PATTERN = re.compile(r"^\{\{.*\}\}$")


def is_rendered(value):
    """Return True if the value is no longer a template placeholder."""
    return not TEMPLATE_PATTERN.match(value.strip())


def get_secret():
    """Return the secret only if it has been rendered by the deploy pipeline."""
    if not is_rendered(SECRET):
        raise EnvironmentError(
            "SECRET_KEY template placeholder was not rendered. "
            "Ensure the deployment pipeline substitutes all {{ ... }} tokens."
        )
    return SECRET


def get_database_url():
    if not is_rendered(DATABASE_URL):
        raise EnvironmentError("DATABASE_URL template was not rendered")
    return DATABASE_URL


if __name__ == "__main__":
    for name, val in [("SECRET", SECRET), ("DATABASE_URL", DATABASE_URL), ("API_KEY", API_KEY)]:
        rendered = is_rendered(val)
        print(f"{name}: {'rendered' if rendered else 'TEMPLATE — not rendered'}")
