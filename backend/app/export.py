"""CSV export of the current table view (events, detections).

- At most MAX_EXPORT_ROWS rows; the X-Export-Truncated header says when more matched.
- Only allow-listed columns, in the order the client asked for.
- CSV-injection safe: a cell that a spreadsheet would read as a formula
  (=, +, -, @, tab, CR) is prefixed with a single quote.
- Callers redact for the user's role before building rows, exactly as the list routes do.
"""

import csv
import io

from fastapi import HTTPException
from fastapi.responses import Response

MAX_EXPORT_ROWS = 5000
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def pick_columns(requested: str | None, allowed: list[str]) -> list[str]:
    """Comma-separated column names from the client, validated against `allowed`."""
    if not requested:
        return allowed
    columns = [c.strip() for c in requested.split(",") if c.strip()]
    if not columns or any(c not in allowed for c in columns):
        raise HTTPException(status_code=422, detail="Unknown export column")
    return list(dict.fromkeys(columns))  # drop duplicates, keep order


def csv_response(rows: list[dict], columns: list[str], filename: str, truncated: bool) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(c)) for c in columns])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Rows": str(len(rows)),
            "X-Export-Truncated": "true" if truncated else "false",
            "Cache-Control": "no-store",
        },
    )
