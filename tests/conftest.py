import pytest

from privacyd.engine import PrivacyEngine
from privacyd.storage import Store
from privacyd.teacher import PrivacyTeacherResponse, parse_teacher_response


class FakeTeacher:
    """Returns a canned response (or raises) and records what it was shown."""
    name = "fake"

    def __init__(self, response=None, error=None):
        self.response, self.error, self.seen = response, error, []

    def analyze(self, request):
        self.seen.append(request)
        if self.error:
            raise self.error
        r = self.response
        return r(request) if callable(r) else r


def resp(**kw) -> PrivacyTeacherResponse:
    data = {"residual_risk": "low"}   # sanitized_text is an optional hint; omitted by default
    data.update(kw)
    return parse_teacher_response(data)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.fixture
def make_engine(store):
    def _make(teacher=None, **kw):
        return PrivacyEngine(store, teacher=teacher, clearance_key=b"k" * 32, **kw)
    return _make


def user_req(text, **extra):
    return {"request": {"model": "m", "messages": [{"role": "user", "content": text}]}, **extra}
