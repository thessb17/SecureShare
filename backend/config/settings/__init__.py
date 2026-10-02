"""Environment specific settings modules.

Select one with DJANGO_SETTINGS_MODULE:

* ``config.settings.dev``  - local development (DEBUG tolerated)
* ``config.settings.prod`` - production / Docker (hardened, HTTPS aware)
* ``config.settings.test`` - pytest (fast hashers, local cache, eager Celery)
"""
