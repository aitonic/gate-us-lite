from __future__ import annotations

import argparse
import contextlib
import json
from pathlib import Path

from .config import ConfigurationError, load_config
from .intel import is_public_ip
from .log import log
from .models import Candidate, candidate_from_dict, candidate_to_dict
from .pipeline import collect, finish, probe_pool, run
from .store import Store
from .tunnel import TunnelProbeUnavailable

PROBE_UNAVAILABLE_EXIT = 3
CONFIGURATION_EXIT = 4


def _write_json(path: str, payload) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")


def _read_json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _read_pool(path: str) -> list[Candidate]:
    return [candidate_from_dict(item) for item in _read_json(path)]


def _read_alive(path: str, pool: list[Candidate]) -> dict[str, str]:
    """Verdicts come from the job that dials untrusted servers, so only plausible entries are kept."""
    if not Path(path).is_file():
        raise TunnelProbeUnavailable(f"no tunnel verdicts at {path}")
    known = {c.dedupe_key for c in pool}
    claimed = _read_json(path).get("alive", {})
    return {key: ip for key, ip in claimed.items() if key in known and isinstance(ip, str) and is_public_ip(ip)}


def _stage_all(args, cfg: dict) -> int:
    with contextlib.closing(Store(args.state)) as store:
        return run(cfg, store, args.output)


def _stage_collect(args, cfg: dict) -> int:
    with contextlib.closing(Store(args.state)) as store:
        _write_json(args.candidates, [candidate_to_dict(c) for c in collect(cfg, store)])
    return 0


def _stage_probe(args, cfg: dict) -> int:
    _write_json(args.verdicts, {"alive": probe_pool(_read_pool(args.candidates), cfg)})
    return 0


def _stage_finish(args, cfg: dict) -> int:
    pool = _read_pool(args.candidates)
    alive = _read_alive(args.verdicts, pool)
    with contextlib.closing(Store(args.state)) as store:
        return finish(cfg, store, pool, alive, args.output)


STAGES = {"all": _stage_all, "collect": _stage_collect, "probe": _stage_probe, "finish": _stage_finish}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate a multi-source US OpenVPN Mihomo YAML")
    ap.add_argument("stage", nargs="?", choices=STAGES, default="all", help="pipeline stage; the default runs all of them in-process")
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--state", default=".state/state.sqlite3")
    ap.add_argument("--output", default="mihomo.yaml")
    ap.add_argument("--candidates", default="handoff/candidates.json", help="candidate pool handed from collect to probe and finish")
    ap.add_argument("--verdicts", default="handoff/verdicts.json", help="tunnel verdicts handed from probe to finish")
    args = ap.parse_args(argv)
    try:
        code = STAGES[args.stage](args, load_config(args.config))
    except TunnelProbeUnavailable as exc:
        log(f"[error] tunnel probe unavailable, nothing is published: {exc}")
        code = PROBE_UNAVAILABLE_EXIT
    except ConfigurationError as exc:
        log(f"[error] configuration, nothing is published: {exc}")
        code = CONFIGURATION_EXIT
    raise SystemExit(code)
