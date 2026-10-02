"""Password policy validators (registered in AUTH_PASSWORD_VALIDATORS)."""
from __future__ import annotations

import re
from typing import Any

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

UPPERCASE_RE = re.compile(r"[A-Z]")
LOWERCASE_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"[0-9]")
SYMBOL_RE = re.compile(r"[^A-Za-z0-9]")


class PasswordComplexityValidator:
    """Require upper case, lower case, digit and symbol characters."""

    def __init__(
        self,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_symbol: bool = True,
    ) -> None:
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_symbol = require_symbol

    def validate(self, password: str, user: Any = None) -> None:
        errors: list[str] = []
        if self.require_uppercase and not UPPERCASE_RE.search(password):
            errors.append(_("at least one uppercase letter"))
        if self.require_lowercase and not LOWERCASE_RE.search(password):
            errors.append(_("at least one lowercase letter"))
        if self.require_digit and not DIGIT_RE.search(password):
            errors.append(_("at least one digit"))
        if self.require_symbol and not SYMBOL_RE.search(password):
            errors.append(_("at least one special character"))
        if errors:
            raise ValidationError(
                _("The password must contain %(requirements)s.")
                % {"requirements": ", ".join(errors)},
                code="password_not_complex",
            )

    def get_help_text(self) -> str:
        return _(
            "Your password must contain uppercase and lowercase letters, "
            "a digit and a special character."
        )


class MaximumLengthValidator:
    """Bound the password length: Argon2 hashing cost grows with input size."""

    def __init__(self, max_length: int = 128) -> None:
        self.max_length = max_length

    def validate(self, password: str, user: Any = None) -> None:
        if len(password) > self.max_length:
            raise ValidationError(
                _("The password must be at most %(max)d characters long.")
                % {"max": self.max_length},
                code="password_too_long",
            )

    def get_help_text(self) -> str:
        return _("Your password must be at most %(max)d characters long.") % {
            "max": self.max_length
        }
