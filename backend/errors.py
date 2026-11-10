"""Domain errors mapped to HTTP statuses by the dispatcher."""
from __future__ import annotations


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.status, self.code, self.message = status, code, message or code


class NotFoundError(ApiError):
    def __init__(self, what: str) -> None:
        super().__init__(404, "not_found", f"{what} not found")


class ConflictError(ApiError):
    def __init__(self, message: str) -> None:
        super().__init__(409, "conflict", message)
