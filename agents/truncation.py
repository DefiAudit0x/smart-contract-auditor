"""Honest truncation / skipped-tool notices (Priority 3, 2026-11-05).

Several audit paths used to cut their input silently — the pipeline's
proportional ``truncate_code``, the per-chunk 4000-char cap, the
second-pass validator's 3000-char code view, the pattern learner's
2000/3000-char prompt slices, and the Telegram bot's 3000/4000-char
caps — and external tools (Slither / Mythril / Aderyn) used to vanish
from the output entirely when they were not installed, leaving only a
log line.  A report that was produced from partial input, or without
a tool the user expected, must say so, with exact lengths.

This module is the single wording source for those notices.  It
contains no detector logic and changes no verdict: callers decide
*where* a notice belongs (appended to a returned report, sent as a
Telegram message, embedded in an LLM prompt), this module only builds
the text so the numbers cannot drift between paths.

Display-only snippet caps (e.g. a 200-char snippet shown next to a
finding, or a 150-char description in a findings list) are NOT input
truncation and are deliberately out of scope: the analysis itself was
not cut, only the rendering of one field.
"""

from typing import List, Optional, Sequence, Tuple

# Section headings are stable strings so tests (and downstream
# parsers) can find them without depending on emoji rendering.
TRUNCATION_SECTION_HEADING = "### Input scope notices"
SKIPPED_TOOLS_HEADING = "### External tools: SKIPPED"


def truncation_notice(where: str, original_len: int, analysed_len: int) -> Optional[str]:
    """One notice line, or ``None`` when nothing was actually cut.

    ``where`` names the step that cut the input (e.g.
    ``"pipeline truncate_code"``); the lengths are character counts,
    so a test can assert them exactly against ``len(code)``.
    """
    if original_len <= analysed_len:
        return None
    omitted = original_len - analysed_len
    return (
        f"- {where}: input truncated — original {original_len} chars, "
        f"analysed {analysed_len} chars "
        f"({omitted} chars were NOT analysed)."
    )


def scope_notices_section(notices: Sequence[str]) -> str:
    """Render collected notice lines as a report section, or ``""``."""
    lines = [n for n in notices if n]
    if not lines:
        return ""
    return (
        f"\n\n{TRUNCATION_SECTION_HEADING}\n"
        + "\n".join(lines)
        + "\n\nThe findings above cover only the analysed portion. "
        "Code beyond the analysed length was not checked by this run."
    )


def append_scope_notices(report: str, notices: Sequence[str]) -> str:
    """Append the scope section to a report, once, if there is one."""
    section = scope_notices_section(notices)
    if not section:
        return report
    if TRUNCATION_SECTION_HEADING in report:
        return report
    return report + section


def skipped_tools_section(skipped: Sequence[Tuple[str, str]]) -> str:
    """Render ``[(tool, reason), ...]`` as a SKIPPED section, or ``""``.

    ``reason`` is a short cause such as ``"not installed"``.  A tool
    that ran and found nothing is NOT skipped and must never appear
    here — absence of findings and absence of the tool are different
    facts, and only the latter belongs in this section.
    """
    items = [(t, r) for t, r in skipped if t]
    if not items:
        return ""
    lines = [SKIPPED_TOOLS_HEADING]
    for tool, reason in items:
        lines.append(f"- {tool}: SKIPPED — {reason}")
    lines.append(
        "\nThese tools did not run, so their checks contributed no "
        "findings to this report (this is not a clean bill from them)."
    )
    return "\n".join(lines)


def append_skipped_tools(report: str, skipped: Sequence[Tuple[str, str]]) -> str:
    """Append the SKIPPED section to a report, once, if there is one."""
    section = skipped_tools_section(skipped)
    if not section:
        return report
    if SKIPPED_TOOLS_HEADING in report:
        return report
    return report + "\n\n" + section
