from __future__ import annotations

import argparse
import logging

from . import clearance
from .api import make_server
from .config import Config
from .engine import PrivacyEngine
from .known_secrets import load_known_secrets
from .policy.approval import decide_approval
from .storage import Store
from .teacher import OpenAITeacher


def build_engine(config: Config, store: Store) -> PrivacyEngine:
    teacher = None
    if config.teacher == "openai":
        teacher = OpenAITeacher(config.teacher_api_key or "", config.teacher_model,
                                config.teacher_base_url, config.teacher_timeout)
    elif config.teacher != "none":
        raise SystemExit(f"unknown teacher provider: {config.teacher}")
    key = clearance.load_or_create_key(config.key_path)
    known = load_known_secrets(config.secret_env_vars, config.secrets_file)
    return PrivacyEngine(store, teacher=teacher, clearance_key=key, known_secrets=known,
                         recent_context_messages=config.recent_context_messages)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="privacyd")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    ap_a = sub.add_parser("approvals")
    ap_a.add_argument("action", choices=["list", "decide"])
    ap_a.add_argument("id", nargs="?")
    ap_a.add_argument("decision", nargs="?", choices=["denied", "allow_once", "allow_class"])
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    config = Config.from_env()
    store = Store(config.db_path)
    if args.cmd == "serve":
        server = make_server(config, build_engine(config, store))
        logging.info("privacyd listening on %s:%s", config.host, config.port)
        server.serve_forever()
    elif args.action == "list":
        for r in store.pending_approvals():
            print(r["id"], r["data_type"], f"L{r['requested_level']}", r["entity_pseudonym"], r["reason"])
    else:
        decide_approval(store, args.id, args.decision)


if __name__ == "__main__":
    main()
