import importlib
import re
import sys
from unittest.mock import patch

import pytest


@pytest.fixture
def application(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("app", None)
    with patch("apscheduler.schedulers.background.BackgroundScheduler.start"):
        module = importlib.import_module("app")
    module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    yield module
    sys.modules.pop("app", None)


def csrf_token(client):
    response = client.get("/")
    assert response.status_code == 200
    match = re.search(
        r'<meta name="csrf-token" content="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match
    return match.group(1)
