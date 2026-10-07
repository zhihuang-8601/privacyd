import sqlite3

from privacyd.storage import Store
from privacyd.storage.sqlite import MIGRATIONS_DIR


def test_existing_v1_database_upgrades_in_place(tmp_path):
    path = tmp_path / "privacy.db"
    db = sqlite3.connect(path)                      # a database created before 0002 existed
    db.executescript((MIGRATIONS_DIR / "0001_init.sql").read_text())
    db.execute("PRAGMA user_version = 1")
    db.execute("INSERT INTO approvals(id, request_id, request_hash, data_type, requested_level,"
               " reason, created_at) VALUES ('a1','r','h','identity',4,'old','2026-10-06')")
    db.commit(); db.close()

    s = Store(path)
    assert s._q("PRAGMA user_version")[0][0] == 2
    old = s.get_approval("a1")
    assert old["session_id"] == "" and old["reason"] == "old"     # old rows survive
    s.set_session_level("s", "[PERSON_001]", "identity", 2)
    assert s.session_level("s", "[PERSON_001]", "identity") == 2
    s.close()
    assert Store(path)._q("PRAGMA user_version")[0][0] == 2       # idempotent re-open
