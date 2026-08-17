"""Manifest-context adapter over the existing, tested parser."""

from __future__ import annotations

from pathlib import Path

from kavach_ai.backend.pipeline.stage1_triage.triage import TriageResult, analyze_apk

from kavach_ai.backend.pipeline.stage2_static.v2_artifacts import (
    ComponentContext, IntentFilterContext, ManifestArtifact,
)


def from_triage(result: TriageResult) -> ManifestArtifact:
    components: list[ComponentContext] = []
    for group in (result.activities, result.services, result.receivers, result.providers):
        for component in group:
            filters = tuple(
                IntentFilterContext(
                    actions=item.actions,
                    categories=item.categories,
                    data=tuple(tuple(sorted(value.items())) for value in item.data),
                )
                for item in component.intent_filters
            )
            components.append(
                ComponentContext(
                    component.component_type, component.name, None,
                    component.exported, filters,
                )
            )
    return ManifestArtifact(
        result.apk_hash, result.package_name, tuple(sorted(result.permissions)),
        tuple(sorted(components)), result.min_sdk, result.target_sdk, result.warnings,
    )


def extract_manifest_artifact(apk_path: str | Path) -> ManifestArtifact:
    """Extract context without using triage score as an analysis gate."""

    return from_triage(analyze_apk(apk_path))
