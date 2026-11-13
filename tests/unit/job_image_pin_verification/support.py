"""Synthetic, per-test inputs; no graph runner, operator inventory or daemon."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.config.host_pins import parse_host_pins, serialize_host_pins


PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64
UNITS = ("selection.resolve_pins", "verification.inspect_images", "publication.publish_handoff")
ATTEMPT = "data/jobs/job_image_pin_verification/attempts/attempt_0001"
CATALOG = b'[[images]]\nid = "tool"\nstate = "enabled"\ntag = "fixture/tool:1"\n'


def pin(source="catalog.tool", tag="fixture/tool:1", image_id=PIN_A):
    return {"source": source, "tag": tag, "image_id": image_id}


def config():
    return SimpleNamespace(
        settings={"enabled": True},
        steps=("selection", "verification", "publication"),
        step=lambda key: SimpleNamespace(tasks={
            "selection": ("resolve_pins",),
            "verification": ("inspect_images",),
            "publication": ("publish_handoff",),
        }[key]),
    )


def context(tmp_path: Path, unit_id: str, outputs=None):
    events, reads = [], []
    outputs = {} if outputs is None else outputs
    run_root = tmp_path / "run"
    step, task = unit_id.split(".")
    unit_root = run_root / ATTEMPT / "steps" / step / "tasks" / task
    unit_root.mkdir(parents=True)

    def output(key):
        reads.append(key)
        return outputs[key]

    return SimpleNamespace(
        job=SimpleNamespace(
            config=config(), repository_root=tmp_path / "repository", run_root=run_root,
            review_policy=SimpleNamespace(releases=SimpleNamespace(values={"platform": "platform-fixture"})),
            events=SimpleNamespace(write=lambda event, **fields: events.append((event, fields))),
        ),
        unit_id=unit_id, unit_root=unit_root, output=output, reads=reads, events=events,
    )


def write_inputs(unit, *, catalog=CATALOG):
    repository = unit.job.repository_root
    catalog_path = repository / "containers/catalog.toml"
    catalog_path.parent.mkdir(parents=True)
    catalog_path.write_bytes(catalog)
    frozen = unit.job.run_root / "data/configuration"
    frozen.mkdir(parents=True)
    host = serialize_host_pins({"fixture/tool:1": PIN_A}, [])
    (frozen / "host-pins.toml").write_bytes(host)
    document = {
        "configuration_host_pins": {
            "sha256": hashlib.sha256(host).hexdigest(),
            "document": parse_host_pins(host),
        },
        "jobs": {},
    }
    (frozen / "resolved.json").write_text(json.dumps(document), encoding="utf-8")
    return catalog_path, frozen / "resolved.json", frozen / "host-pins.toml"


def matching_runner(argv, timeout):
    assert tuple(argv) == ("docker", "image", "inspect", "fixture/tool:1", "--format", "{{.Id}}")
    assert timeout == 60
    return 0, (PIN_A + "\n").encode(), b"", False


def artifact(unit, name):
    path = unit.unit_root / name
    content = path.read_bytes()
    identity = {
        "path": path.relative_to(unit.job.run_root).as_posix(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }
    return identity, json.loads(content)
