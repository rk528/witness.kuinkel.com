"""Translate every rule into the query languages of the SIEMs it is meant for.

The output lives in `queries/<target>/<stem>.<ext>` and is committed, so anyone can
copy a query straight from GitHub. CI runs `witness build --check` to make sure the
committed queries still match the rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from .suite import ROOT

QUERIES_DIR = ROOT / "queries"


def asim_original_filename_fix() -> ProcessingPipeline:
    """Map OriginalFileName before the ASIM pipeline does.

    pySigma's ASIM mapping sends OriginalFileName to both TargetProcessFileOriginalName
    and TargetProcessFilename, and then rejects the second because imProcessCreate has
    no such column. Mapping it to the real column first sidesteps that.
    """
    return ProcessingPipeline(
        name="witness: ASIM OriginalFileName fix",
        priority=5,
        items=[
            ProcessingItem(
                identifier="witness_asim_original_filename",
                transformation=FieldMappingTransformation(
                    {"OriginalFileName": "TargetProcessFileOriginalName"}
                ),
            )
        ],
    )


@dataclass(frozen=True)
class Target:
    key: str
    label: str
    ext: str
    backend: Callable[[], object]


TARGETS = [
    Target(
        "sentinel",
        "Microsoft Sentinel (ASIM, KQL)",
        "kql",
        lambda: KustoBackend(asim_original_filename_fix() + sentinel_asim_pipeline()),
    ),
    Target(
        "defender",
        "Microsoft Defender XDR (KQL)",
        "kql",
        lambda: KustoBackend(microsoft_xdr_pipeline()),
    ),
    Target(
        "splunk",
        "Splunk (Sysmon, SPL)",
        "spl",
        lambda: SplunkBackend(sysmon_pipeline() + splunk_windows_pipeline()),
    ),
]


def query_path(target: Target, stem: str) -> Path:
    return QUERIES_DIR / target.key / f"{stem}.{target.ext}"


def convert(rule_path: Path, target: Target) -> str:
    # Pipelines rewrite the rule in place, so each target gets a freshly parsed copy.
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    queries = target.backend().convert(collection)
    return "\n".join(queries) + "\n"


def render_all(rule_paths: list[Path]) -> dict[Path, str]:
    return {
        query_path(target, path.stem): convert(path, target)
        for path in rule_paths
        for target in TARGETS
    }
