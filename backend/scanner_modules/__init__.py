"""Plugin scanner modules wrapping the legacy ``services/scanner`` services.

Each module registers with the :class:`app.scanning.registry.ScannerRegistry`
via ``@scanner_module`` and consumes an immutable :class:`ScanContext`.
Modules only *collect* data; persistence stays in the pipeline so the registry
stays side-effect free and testable.
"""