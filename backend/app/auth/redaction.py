"""Server-side command-line redaction for roles without "view_command_lines" (viewers).

Structured fields are replaced outright: command_line -> "<process> [redacted for viewer role]".
Free text that may quote a command (investigation items, AI narrative, chat answers) goes
through TextRedactor, which replaces each known command line of the incident's events, and
then any long argument taken from those command lines (URLs, paths, encoded payloads)."""

import re

from sqlalchemy.orm import Session

from app.analysis.investigation import safe_command
from app.auth.permissions import can
from app.models import Event, User

REDACTED = "[redacted for viewer role]"
MIN_ARG_LENGTH = 12  # shorter arguments ("-k", "/c", "netsvcs") are not sensitive on their own


def sees_command_lines(user: User) -> bool:
    return can(user, "view_command_lines")


def process_name(process: str | None, command_line: str | None = None) -> str:
    source = process or (command_line.split()[0] if command_line and command_line.split() else "")
    return re.split(r"[\\/]", source.strip('"'))[-1] or "process"


def redact_command(command_line: str | None, process: str | None) -> str | None:
    if not command_line:
        return command_line
    return f"{process_name(process, command_line)} {REDACTED}"


class TextRedactor:
    def __init__(self, events: list[Event]):
        replacements: dict[str, str] = {}
        args: set[str] = set()
        for e in events:
            if not e.command_line:
                continue
            masked = redact_command(e.command_line, e.process)
            for form in (e.command_line, " ".join(e.command_line.split()), safe_command(e.command_line)):
                if form:
                    replacements[form] = masked
            name = process_name(e.process, e.command_line).lower()
            for arg in (a.strip("\"'") for a in e.command_line.split()):
                # Skip the executable path itself: its name stays visible in the masked text.
                if len(arg) >= MIN_ARG_LENGTH and not arg.lower().endswith(name):
                    args.add(arg)
        # Longest first, so a full command is replaced before any of its parts.
        self.replacements = sorted(replacements.items(), key=lambda kv: -len(kv[0]))
        self.args = sorted(args, key=len, reverse=True)

    def text(self, value: str) -> str:
        for needle, masked in self.replacements:
            value = value.replace(needle, masked)
        for arg in self.args:
            value = value.replace(arg, "[redacted]")
        return value

    def apply(self, value):
        """Redact every string inside nested dicts/lists (e.g. a model_dump())."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.apply(v) for v in value]
        if isinstance(value, dict):
            return {k: self.apply(v) for k, v in value.items()}
        return value


def redactor_for(db: Session, event_ids: list[str]) -> TextRedactor:
    events = db.query(Event).filter(Event.id.in_(set(event_ids))).all() if event_ids else []
    return TextRedactor(events)
