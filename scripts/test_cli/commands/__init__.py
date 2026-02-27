"""Commands for SecurePDF Test CLI."""

# Commands are lazily loaded when accessed
__all__ = [
    "register_encryption_command",
    "register_provenance_command",
    "register_foundation_command",
    "register_e2e_encryption_command",
]


def register_encryption_command(app):
    """Register the encryption command."""
    from .encryption import encryption

    app.command()(encryption)


def register_provenance_command(app):
    """Register the provenance command."""
    from .provenance import provenance

    app.command()(provenance)


def register_foundation_command(app):
    """Register the foundation verification command."""
    from .foundation import verify_foundation

    app.command()(verify_foundation)


def register_e2e_encryption_command(app):
    """Register the e2e encryption command."""
    from .e2e import e2e_encryption

    app.command()(e2e_encryption)
