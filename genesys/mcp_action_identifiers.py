"""IDs literais de Data Actions Genesys para consultas MCP somente leitura.

Estes identificadores são recebidos de GET /integrations/actions. O prefixo e o
slug são parte da identidade do recurso e não devem ser removidos.
Aceita somente segmentos de rota, nunca URL, path, query ou fragment.
"""
from __future__ import annotations

import re
from uuid import UUID

_UUID = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
_STATIC_NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"
ACTION_ID_SEGMENT_PATTERN = (
    rf"(?:"
    rf"(?:static_|custom_-_)?{_UUID}"
    rf"|static_-_{_STATIC_NAME}_-_{_UUID}"
    rf")"
)
ACTION_ID_MAX_LENGTH = len("static_-_") + 128 + len("_-_") + 36
_ACTION_ID = re.compile(rf"\A{ACTION_ID_SEGMENT_PATTERN}\Z")
_TRAILING_UUID = re.compile(rf"(?P<uuid>{_UUID})\Z")


def normalize_mcp_action_id(raw_id: object) -> str:
    """Valida o ID integral e normaliza exclusivamente o UUID final."""
    if (
        not isinstance(raw_id, str)
        or len(raw_id) > ACTION_ID_MAX_LENGTH
        or _ACTION_ID.fullmatch(raw_id) is None
    ):
        raise ValueError("ID de Data Action MCP inválido.")
    match = _TRAILING_UUID.search(raw_id)
    if match is None:
        raise ValueError("ID de Data Action MCP inválido.")
    return raw_id[:match.start("uuid")] + str(UUID(match.group("uuid")))
