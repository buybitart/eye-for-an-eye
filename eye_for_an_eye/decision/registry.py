"""P9 local model registry: ACTIVE and CANDIDATE roles, atomic promotion, rollback.

There is no central service. The registry is a directory and one small pointer
file.

Model versions are immutable directories under `versions/`. ACTIVE and CANDIDATE
are *names* in `registry.json`, not copies of files. Promotion is therefore a
single atomic pointer write: there is no window in which a half-written active
model can be loaded, and rollback is the same operation in reverse.

A candidate begins with zero deployment authority. Nothing here promotes
automatically.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .features import INPUT_ORDER, SCHEMA_VERSION

REGISTRY_VERSION = 1
ACTIVE = 'ACTIVE'
CANDIDATE = 'CANDIDATE'
ARCHIVED = 'ARCHIVED'
VERSION_PATTERN = re.compile(r'[A-Za-z0-9_.-]{1,80}')
MAX_ARTIFACT_BYTES = 33_554_432
ARTIFACTS = ('classifier.onnx', 'manifest.json', 'distribution.json')
#: A model with no declared scope is a global one. Every model written before
#: P12 is exactly that, so the default keeps old registries readable.
GLOBAL_SCOPE = 'GLOBAL'
AUDIT_LIMIT = 200


class RegistryError(ValueError):
    """The registry state or a candidate artifact is not acceptable."""


def _digest(path):
    sha = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def _write_atomic(path, data):
    """Write a file so a reader never sees a partial version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix='.tmp-')
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    # Durably record the rename itself, so a crash cannot resurrect the old file.
    try:
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        pass


@dataclass(frozen=True, slots=True)
class ModelVersion:
    version: str
    role: str
    path: str
    model_version: str = ''
    dataset_version: str = ''
    parent_model: str = ''
    feature_schema_version: int = SCHEMA_VERSION
    created_at: str = ''
    sha256: str = ''
    recommended_mode: str = ''
    has_distribution: bool = False
    #: `GLOBAL`, or `SITE:<site-id>`. Absent in pre-P12 manifests, which are
    #: global by definition, so the default keeps old registries readable.
    scope: str = GLOBAL_SCOPE

    def explain(self):
        return {'version': self.version, 'role': self.role, 'scope': self.scope,
                'dataset_version': self.dataset_version,
                'parent_model': self.parent_model, 'feature_schema_version': self.feature_schema_version,
                'created_at': self.created_at, 'sha256': self.sha256[:16],
                'recommended_mode': self.recommended_mode, 'has_distribution': self.has_distribution}


@dataclass(frozen=True, slots=True)
class RegistryState:
    active: str | None = None
    candidate: str | None = None
    previous_active: str | None = None
    audit: tuple[dict, ...] = field(default_factory=tuple)

    def explain(self):
        return {'active': self.active, 'candidate': self.candidate,
                'previous_active': self.previous_active, 'audit_entries': len(self.audit)}


class ModelRegistry:
    """Filesystem registry. Roles are pointers; version directories are immutable.

    A registry has a *scope*: `GLOBAL`, or `SITE:<site-id>`. One registry
    directory holds models for one scope, which is what makes per-site promotion
    and rollback fall out for free — each scope has its own pointer file, so
    rolling site A back is a write to site A's pointer and touches nothing else.

    The scope is also checked against every manifest published into it. A model
    built for one site landing in another site's registry is the mix-up worth
    preventing structurally: it would run, produce plausible numbers, and be
    wrong in a way nothing downstream could detect.
    """

    def __init__(self, root, *, scope=GLOBAL_SCOPE):
        self.root = Path(root)
        self.scope = scope or GLOBAL_SCOPE
        self.versions_dir = self.root / 'versions'
        self.pointer = self.root / 'registry.json'

    # --- state ---------------------------------------------------------

    def _load(self):
        if not self.pointer.is_file():
            return RegistryState()
        try:
            payload = json.loads(self.pointer.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise RegistryError(f'registry pointer is unreadable: {exc}') from exc
        if payload.get('registry_version') != REGISTRY_VERSION:
            raise RegistryError('unsupported registry_version')
        return RegistryState(active=payload.get('active'), candidate=payload.get('candidate'),
                             previous_active=payload.get('previous_active'),
                             audit=tuple(payload.get('audit', [])))

    def _save(self, state, event, detail):
        """Persist roles and append one audit entry, atomically."""
        audit = list(state.audit)
        audit.append({'at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                      'event': event, **detail})
        audit = audit[-AUDIT_LIMIT:]
        payload = {'registry_version': REGISTRY_VERSION, 'active': state.active,
                   'candidate': state.candidate, 'previous_active': state.previous_active,
                   'audit': audit}
        _write_atomic(self.pointer, json.dumps(payload, indent=2, sort_keys=True).encode('utf-8'))
        return RegistryState(state.active, state.candidate, state.previous_active, tuple(audit))

    @property
    def state(self):
        return self._load()

    # --- reading -------------------------------------------------------

    def version_path(self, version):
        if not VERSION_PATTERN.fullmatch(version or ''):
            raise RegistryError('invalid model version identifier')
        path = (self.versions_dir / version).resolve()
        # Reject anything that escapes the registry, however it was spelled.
        if not str(path).startswith(str(self.versions_dir.resolve()) + os.sep):
            raise RegistryError('model version escapes the registry directory')
        return path

    def describe_version(self, version, role=ARCHIVED):
        path = self.version_path(version)
        manifest_path = path / 'manifest.json'
        if not manifest_path.is_file():
            raise RegistryError(f'{version}: manifest.json is missing')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        model_file = path / 'classifier.onnx'
        return ModelVersion(version=version, role=role, path=str(path),
            scope=manifest.get('scope', GLOBAL_SCOPE),
            model_version=manifest.get('model_version', ''),
            dataset_version=manifest.get('training_dataset_version') or manifest.get('dataset_version', ''),
            parent_model=manifest.get('parent_model', ''),
            feature_schema_version=manifest.get('feature_schema_version', SCHEMA_VERSION),
            created_at=manifest.get('created_at', ''),
            sha256=_digest(model_file) if model_file.is_file() else '',
            recommended_mode=manifest.get('recommended_mode', ''),
            has_distribution=(path / 'distribution.json').is_file())

    def list_versions(self):
        if not self.versions_dir.is_dir():
            return []
        state = self._load()
        roles = {state.active: ACTIVE, state.candidate: CANDIDATE}
        found = []
        for entry in sorted(self.versions_dir.iterdir()):
            if not entry.is_dir():
                continue
            try:
                found.append(self.describe_version(entry.name, roles.get(entry.name, ARCHIVED)))
            except (RegistryError, ValueError, OSError):
                continue
        return found

    def resolve(self, role):
        """Paths for a role, or None. Used by the runtime to load a model."""
        state = self._load()
        version = state.active if role == ACTIVE else state.candidate
        if not version:
            return None
        path = self.version_path(version)
        if not (path / 'classifier.onnx').is_file():
            return None
        distribution = path / 'distribution.json'
        return {'version': version, 'model_path': str(path / 'classifier.onnx'),
                'manifest_path': str(path / 'manifest.json'),
                'distribution_path': str(distribution) if distribution.is_file() else ''}

    # --- writing -------------------------------------------------------

    def _validate_artifacts(self, staging, version):
        """Refuse a candidate that is not a complete, self-consistent model."""
        manifest_path = staging / 'manifest.json'
        model_path = staging / 'classifier.onnx'
        for required in (manifest_path, model_path):
            if not required.is_file():
                raise RegistryError(f'{version}: {required.name} is missing')
        size = model_path.stat().st_size
        if not 0 < size <= MAX_ARTIFACT_BYTES:
            raise RegistryError(f'{version}: model artifact size {size} is out of range')
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        except ValueError as exc:
            raise RegistryError(f'{version}: manifest is not valid JSON') from exc
        if manifest.get('feature_schema_version') != SCHEMA_VERSION:
            raise RegistryError(f'{version}: feature schema does not match this build')
        if manifest.get('model_version') != version:
            raise RegistryError(f'{version}: manifest model_version does not match the directory name')
        # A model built for one scope must never be published into another. It
        # would load, run, and give confident answers computed against the wrong
        # site's notion of normal — a failure with no symptom.
        declared = manifest.get('scope', GLOBAL_SCOPE)
        if declared != self.scope:
            raise RegistryError(
                f'{version}: this model declares scope {declared!r} but the registry '
                f'is {self.scope!r}; a model for one site must not be loaded for another')
        order = manifest.get('feature_order')
        if order is not None and list(order) != list(INPUT_ORDER):
            raise RegistryError(f'{version}: feature order does not match this build')
        digest = _digest(model_path)
        if manifest.get('sha256') and manifest['sha256'] != digest:
            raise RegistryError(f'{version}: model SHA256 does not match its manifest')
        return manifest, digest

    def register_candidate(self, version, artifacts):
        """Stage, validate, then publish a candidate in one atomic pointer write.

        `artifacts` maps file name to bytes. The version directory is written
        into a staging area first, so a rejected candidate leaves nothing behind
        and the registry is never partially populated.
        """
        if not VERSION_PATTERN.fullmatch(version or ''):
            raise RegistryError('invalid model version identifier')
        target = self.version_path(version)
        if target.exists():
            raise RegistryError(f'{version} already exists; model versions are immutable')
        unknown = set(artifacts) - set(ARTIFACTS) - {'model-card.md', 'evaluation.json'}
        if unknown:
            raise RegistryError(f'unexpected artifact names: {sorted(unknown)}')
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=str(self.versions_dir), prefix='.staging-'))
        try:
            for name, data in artifacts.items():
                _write_atomic(staging / name, data)
            self._validate_artifacts(staging, version)
            # mkdtemp creates the staging directory as 0o700. A sensor running
            # as another user could not read it. Set the mode explicitly.
            os.chmod(staging, 0o755)
            os.replace(staging, target)
        except BaseException:
            for child in staging.glob('*'):
                child.unlink(missing_ok=True)
            staging.rmdir()
            raise
        state = self._load()
        state = RegistryState(state.active, version, state.previous_active, state.audit)
        return self._save(state, 'candidate_registered', {'version': version})

    def promote(self, version, *, gate_passed, reason=''):
        """Make a version ACTIVE. Refuses unless a quality gate passed.

        The previous ACTIVE is recorded, never deleted, so rollback always has
        somewhere to go.
        """
        if not gate_passed:
            raise RegistryError('promotion requires a passing quality gate')
        target = self.version_path(version)
        if not (target / 'classifier.onnx').is_file():
            raise RegistryError(f'{version} is not a registered model version')
        self.describe_version(version)  # re-read and validate the manifest
        state = self._load()
        if state.active == version:
            raise RegistryError(f'{version} is already ACTIVE')
        promoted = RegistryState(active=version,
                                 candidate=None if state.candidate == version else state.candidate,
                                 previous_active=state.active, audit=state.audit)
        return self._save(promoted, 'promoted', {'version': version, 'previous': state.active,
                                                 'reason': reason[:200]})

    def rollback(self, *, reason=''):
        """Restore the previous ACTIVE. Local, offline, and always available."""
        state = self._load()
        if not state.previous_active:
            raise RegistryError('no previous active model to roll back to')
        target = self.version_path(state.previous_active)
        if not (target / 'classifier.onnx').is_file():
            raise RegistryError('the previous active model is no longer on disk')
        restored = RegistryState(active=state.previous_active, candidate=state.candidate,
                                 previous_active=state.active, audit=state.audit)
        return self._save(restored, 'rolled_back', {'version': state.previous_active,
                                                    'replaced': state.active, 'reason': reason[:200]})

    def reject_candidate(self, reason=''):
        """Clear the candidate role. The version directory stays for the record."""
        state = self._load()
        if not state.candidate:
            raise RegistryError('there is no candidate to reject')
        cleared = RegistryState(state.active, None, state.previous_active, state.audit)
        return self._save(cleared, 'candidate_rejected', {'version': state.candidate,
                                                          'reason': reason[:200]})

    def prunable(self):
        """Versions that retention may remove. ACTIVE and its fallback never appear."""
        state = self._load()
        protected = {state.active, state.candidate, state.previous_active} - {None}
        return [v.version for v in self.list_versions() if v.version not in protected]
