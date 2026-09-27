"""Which model answers for which site, and what happens when one is broken.

## Why not a model per site

The obvious multi-site design is one model per website, and for most
deployments it is a bad idea. A small site may see a few hundred requests a day
and almost no confirmed malicious ones. A classifier trained on twenty labelled
examples is not a classifier; it is a memory of twenty examples wearing a
confidence score.

So the order of preference is:

1. one validated **base model**, shared by every site;
2. plus that site's own **statistical baseline**, which needs no labels and
   works from day one;
3. plus that site's **policy**, which is where operational knowledge belongs;
4. and only then, where a site really has enough trusted labelled data, an
   optional site-specific model.

That order is why `SiteProfile.model_scope` defaults to empty. Most sites should
never have a model of their own, and the architecture treats that as the normal
case rather than a deficiency.

## Loading one model once

Every site using the base model shares one loaded instance. Loading the same
ONNX file once per site would multiply memory by the number of sites for no
benefit — the file is identical and inference is stateless.

## Failure is per site

A site whose model is missing, corrupt, or built against a different feature
schema falls back to the base model and says so. It does not take the sensor
down and it does not affect any other site. The fallback chain always ends
somewhere that works: site model → base model → no model at all, which is the
deterministic mathematical engine, which was never optional.
"""
from dataclasses import dataclass
import threading

from ..decision.features import SCHEMA_VERSION
from ..decision.registry import (ACTIVE, GLOBAL_SCOPE, ModelRegistry, RegistryError)
from .identity import normalise_site_id

SITE_MODEL_SCHEMA_VERSION = 1

#: How a site scope is spelled in a manifest.
SITE_SCOPE_PREFIX = 'SITE:'

#: Why a particular model ended up being the one used.
SITE_MODEL = 'site_model'
BASE_MODEL = 'base_model'
NO_MODEL = 'no_model'


class SiteModelError(ValueError):
    """A model cannot be resolved for a site."""


def site_scope(site_id):
    """The manifest scope string for one site."""
    cleaned = normalise_site_id(site_id)
    if not cleaned:
        raise SiteModelError('a site scope needs a site id')
    return f'{SITE_SCOPE_PREFIX}{cleaned}'


def parse_scope(scope):
    """`('GLOBAL', '')` or `('SITE', '<site-id>')`. Raises on anything else."""
    text = str(scope or GLOBAL_SCOPE)
    if text == GLOBAL_SCOPE:
        return GLOBAL_SCOPE, ''
    if text.startswith(SITE_SCOPE_PREFIX):
        site = normalise_site_id(text[len(SITE_SCOPE_PREFIX):])
        if not site:
            raise SiteModelError(f'{scope!r} names no site')
        return 'SITE', site
    raise SiteModelError(
        f'unknown model scope {scope!r}; expected {GLOBAL_SCOPE} or '
        f'{SITE_SCOPE_PREFIX}<site-id>')


@dataclass(frozen=True)
class Resolution:
    """Which model a site got, and why that one.

    `reasons` is populated when something did not go to plan. A site quietly
    running on the base model because its own model failed to load looks
    identical, from the outside, to a site that was configured that way — so the
    difference is written down.
    """

    site_id: str
    source: str
    scope: str = GLOBAL_SCOPE
    version: str = ''
    path: str = ''
    reasons: tuple = ()

    @property
    def fell_back(self):
        return bool(self.reasons)

    def explain(self):
        return {'site_model_schema_version': SITE_MODEL_SCHEMA_VERSION,
                'site_id': self.site_id, 'model_source': self.source,
                'model_scope': self.scope, 'model_version': self.version,
                'fell_back': self.fell_back, 'reasons': list(self.reasons)}


class SiteModelRegistry:
    """One `ModelRegistry` per scope, under one root.

        <root>/global/            the base model, shared by every site
        <root>/sites/<site-id>/   optional, per site

    Each scope keeps its own pointer file, which is what makes promotion and
    rollback naturally site-scoped: rolling site A back writes site A's pointer
    and cannot touch site B's.
    """

    def __init__(self, root, *, max_sites=64):
        from pathlib import Path
        self.root = Path(root)
        self.max_sites = max(1, int(max_sites))
        self._registries = {}
        self._lock = threading.Lock()

    def global_registry(self):
        return self._registry(GLOBAL_SCOPE)

    def site_registry(self, site_id):
        return self._registry(site_scope(site_id))

    def _registry(self, scope):
        with self._lock:
            existing = self._registries.get(scope)
            if existing is not None:
                return existing
            kind, site = parse_scope(scope)
            if kind == GLOBAL_SCOPE:
                path = self.root / 'global'
            else:
                if len([key for key in self._registries
                        if key != GLOBAL_SCOPE]) >= self.max_sites:
                    raise SiteModelError(
                        f'more than {self.max_sites} site registries; this bound '
                        'keeps model storage and open handles bounded')
                path = self.root / 'sites' / site
            registry = ModelRegistry(path, scope=scope)
            self._registries[scope] = registry
            return registry

    def configured_sites(self):
        """Sites that actually have a registry directory on disk."""
        directory = self.root / 'sites'
        if not directory.is_dir():
            return ()
        return tuple(sorted(entry.name for entry in directory.iterdir()
                            if entry.is_dir()))

    def health(self):
        document = {'site_model_schema_version': SITE_MODEL_SCHEMA_VERSION,
                    'root': str(self.root), 'sites': list(self.configured_sites())}
        try:
            document['global'] = self.global_registry().state.explain()
        except RegistryError as exc:
            document['global'] = {'error': str(exc)}
        return document


class ModelResolver:
    """Picks the model for a site, validates it, and falls back safely.

    The rule (§34): a site's own validated active model if it has one, otherwise
    the base model. Feature schema is checked every time — a model built against
    a different feature vector does not fail loudly at inference, it produces
    numbers computed from the wrong columns.

    Resolutions are cached per site so that a busy site does not re-read a
    manifest per request, and the cache is keyed by site rather than by model so
    that two sites sharing the base model share one loaded instance.
    """

    #: The cache holds one entry per site asked about. Sites are configured, so
    #: in production this is small — but `resolve()` accepts any string, and a
    #: future caller that passed a `Host:`-derived id straight in would make it
    #: attacker-keyed. The bound belongs here rather than in the callers.
    MAX_CACHED_SITES = 256

    def __init__(self, registry, *, schema_version=SCHEMA_VERSION,
                 max_cached_sites=MAX_CACHED_SITES):
        self.registry = registry
        self.schema_version = schema_version
        self.max_cached_sites = max(1, int(max_cached_sites))
        self._cache = {}
        self._lock = threading.Lock()

    def invalidate(self, site_id=None):
        """Forget cached resolutions, after a promotion or a rollback.

        Kept for a caller in the same process, but nothing depends on it being
        called: `resolve()` notices a changed pointer on its own. Rollback is run
        from a separate CLI process, so an in-process hook could never have been
        the mechanism that made it take effect.
        """
        with self._lock:
            if site_id is None:
                self._cache.clear()
            else:
                self._cache.pop(normalise_site_id(site_id), None)

    def _fingerprint(self, site):
        """A cheap stamp of the pointer files this site's answer depends on.

        Two `stat` calls. That is the price of `model rollback` reaching a
        sensor that is already running, and it is worth paying: the operator
        runs the rollback in a *different process* from the sensor, so nothing
        in the sensor would otherwise learn that the model it is using has been
        withdrawn. A cache with no invalidation signal turns the emergency lever
        into a no-op until somebody thinks to restart the service — during the
        incident the lever exists for.
        """
        stamps = []
        for scope in ((site_scope(site),) if site else ()) + (GLOBAL_SCOPE,):
            try:
                kind, scoped = parse_scope(scope)
                root = (self.registry.root / 'global' if kind == GLOBAL_SCOPE
                        else self.registry.root / 'sites' / scoped)
                info = (root / 'registry.json').stat()
                stamps.append((scope, info.st_mtime_ns, info.st_size, info.st_ino))
            except (SiteModelError, OSError, AttributeError):
                stamps.append((scope, None, None, None))
        return tuple(stamps)

    def resolve(self, site_id, *, prefer_site_model=True):
        """Which model answers for this site. Never raises."""
        site = normalise_site_id(site_id)
        stamp = self._fingerprint(site)
        with self._lock:
            cached = self._cache.get(site)
        if cached is not None and cached[0] == stamp:
            return cached[1]
        resolution = self._resolve(site, prefer_site_model)
        with self._lock:
            if len(self._cache) >= self.max_cached_sites and site not in self._cache:
                # Least-recently-inserted. A resolution is cheap to rebuild, so
                # the eviction policy matters far less than the bound existing.
                self._cache.pop(next(iter(self._cache)), None)
            self._cache[site] = (stamp, resolution)
        return resolution

    def _resolve(self, site, prefer_site_model):
        reasons = []

        if site and prefer_site_model:
            found, why = self._try(site_scope(site), site)
            if found is not None:
                return found
            if why:
                reasons.append(why)

        found, why = self._try(GLOBAL_SCOPE, site)
        if found is not None:
            return Resolution(site_id=site, source=BASE_MODEL, scope=GLOBAL_SCOPE,
                              version=found.version, path=found.path,
                              reasons=tuple(reasons))
        if why:
            reasons.append(why)

        # No usable model anywhere. This is not an outage: the deterministic
        # mathematical engine has never depended on a model, and a site with no
        # classifier is a site running on maths and its own baseline.
        reasons.append('no usable model; the mathematical engine decides alone')
        return Resolution(site_id=site, source=NO_MODEL, scope='',
                          reasons=tuple(reasons))

    def _try(self, scope, site):
        """`(Resolution, None)` when a scope yields a usable active model."""
        try:
            kind, scoped_site = parse_scope(scope)
            registry = (self.registry.global_registry() if kind == GLOBAL_SCOPE
                        else self.registry.site_registry(scoped_site))
            resolved = registry.resolve(ACTIVE)
        except (SiteModelError, RegistryError, OSError) as exc:
            return None, f'{scope}: {type(exc).__name__}'
        if not resolved:
            return None, ''

        version = resolved.get('version', '')
        try:
            described = registry.describe_version(version, ACTIVE)
        except (RegistryError, OSError, ValueError) as exc:
            return None, (f'{scope}: the active model {version!r} could not be read '
                          f'({type(exc).__name__}); falling back')

        if described.scope != scope:
            # Belt and braces: the registry already refuses to publish a
            # mismatched manifest, so reaching here means something changed the
            # files underneath it.
            return None, (f'{scope}: the active model declares scope '
                          f'{described.scope!r}; refusing to use another site\'s model')

        if described.feature_schema_version != self.schema_version:
            return None, (f'{scope}: model {version!r} was built for feature schema '
                          f'{described.feature_schema_version}, this build uses '
                          f'{self.schema_version}; falling back rather than feeding '
                          'it the wrong columns')

        source = BASE_MODEL if kind == GLOBAL_SCOPE else SITE_MODEL
        return Resolution(site_id=site, source=source, scope=scope,
                          version=version, path=resolved.get('path', '')), None

    def health(self, sites=()):
        return {'site_model_schema_version': SITE_MODEL_SCHEMA_VERSION,
                'feature_schema_version': self.schema_version,
                'resolutions': {site: self.resolve(site).explain() for site in sites},
                'note': ('a site without its own model uses the shared base model; '
                         'that is the intended arrangement, not a deficiency')}
