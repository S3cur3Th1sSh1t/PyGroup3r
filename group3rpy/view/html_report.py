"""Filterable single-file HTML report.

This is an ADDITION to Group3r's output formats, not a port -- the `nice` and
`json` printers remain byte-identical to the original. It exists because real
reports from large domains run to hundreds of megabytes, which is unusable as
flat text.

Scale strategy, in order of importance:

1. **String interning.** The same finding reason, detail, setting type and GPO
   name repeat thousands of times across a domain. Every string is stored once in
   a dictionary and referenced by integer index.
2. **Columnar layout.** Filterable fields live in parallel arrays, so the browser
   filters over compact integer arrays rather than walking objects.
3. **Search over the dictionary, not the rows.** A query is matched against the
   ~thousands of *distinct* strings once, producing a match set; each row then
   just tests whether any of its field indices is in that set. Search cost scales
   with vocabulary size, not with finding count.
4. **gzip + base64 embedding.** The payload is compressed before being inlined and
   inflated in the browser with `DecompressionStream`. On this kind of highly
   repetitive data that is typically a 10-20x reduction, which is what keeps a
   single portable file practical.
5. **Virtualised rendering.** Only the visible rows are ever in the DOM.

The result is one self-contained .html file with no external dependencies, which
is what makes it safe to hand to a client.
"""

import base64
import datetime
import gzip
import html
import json
import os
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..classifiers.constants import Triage
from .finding_help import entries_for_payload, lookup_slug, slug_order

_HELP_ORDER = slug_order()

_TEMPLATE_NAME = "report_template.html"

# Fields on a setting that carry no analytical value in the report body.
_SKIPPED_SETTING_FIELDS = {"policy_type", "is_morphed"}

# Depth limit when flattening nested setting objects into key/value rows.
_MAX_DEPTH = 3


class StringTable:
    """Interning table: maps each distinct string to a stable integer index."""

    def __init__(self):
        self._index: Dict[str, int] = {}
        self.strings: List[str] = []

    def intern(self, value: Optional[str]) -> int:
        """Return the index for `value`. Index 0 is always the empty string."""
        if value is None:
            value = ""
        if not isinstance(value, str):
            value = str(value)
        existing = self._index.get(value)
        if existing is not None:
            return existing
        index = len(self.strings)
        self._index[value] = index
        self.strings.append(value)
        return index


def _scalar(value: Any) -> Optional[str]:
    """Render a leaf value as display text, or None if it should be skipped."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    return None


def _flatten(obj: Any, prefix: str = "", depth: int = 0) -> List[Tuple[str, str]]:
    """Flatten a setting (or any nested dataclass/list) into key/value pairs.

    Keeps the report's detail pane and its full-text search working off the same
    structure, so anything visible is also searchable.
    """
    out: List[Tuple[str, str]] = []
    if depth > _MAX_DEPTH or obj is None:
        return out

    if is_dataclass(obj) and not isinstance(obj, type):
        for field in fields(obj):
            if field.name in _SKIPPED_SETTING_FIELDS and not prefix:
                continue
            value = getattr(obj, field.name, None)
            label = f"{prefix}{field.name}"
            out.extend(_flatten(value, f"{label}.", depth + 1) if _is_container(value) else [])
            if not _is_container(value):
                text = _scalar(value)
                if text is not None:
                    out.append((label, text))
        return out

    if isinstance(obj, dict):
        for key, value in obj.items():
            label = f"{prefix}{key}"
            if _is_container(value):
                out.extend(_flatten(value, f"{label}.", depth + 1))
            else:
                text = _scalar(value)
                if text is not None:
                    out.append((label, text))
        return out

    if isinstance(obj, (list, tuple, set)):
        for position, item in enumerate(obj):
            label = f"{prefix.rstrip('.')}[{position}]"
            if _is_container(item):
                out.extend(_flatten(item, f"{label}.", depth + 1))
            else:
                text = _scalar(item)
                if text is not None:
                    out.append((label, text))
        return out

    text = _scalar(obj)
    if text is not None:
        out.append((prefix.rstrip("."), text))
    return out


def _is_container(value: Any) -> bool:
    if isinstance(value, (str, bytes, bool, int, float, Enum)) or value is None:
        return False
    if isinstance(value, (datetime.datetime, datetime.date)):
        return False
    return is_dataclass(value) or isinstance(value, (list, tuple, set, dict))


def _ace_rows(aces, table: StringTable) -> List[List[int]]:
    """Serialise a SimpleAce list to [trusteeIdx, sidIdx, typeIdx, rightsIdx]."""
    rows: List[List[int]] = []
    for ace in aces or []:
        trustee = getattr(ace, "trustee", None)
        rows.append(
            [
                table.intern(getattr(trustee, "display_name", None)),
                table.intern(getattr(trustee, "sid", None)),
                table.intern(
                    ace.ace_type.name if getattr(ace, "ace_type", None) else None
                ),
                table.intern(", ".join(getattr(ace, "rights", None) or [])),
            ]
        )
    return rows


def _path_rows(path_findings, table: StringTable) -> List[List[int]]:
    """Serialise PathResults to a compact row per assessed path."""
    rows: List[List[int]] = []
    for result in path_findings or []:
        rw = getattr(result, "rw_status", None)
        rows.append(
            [
                table.intern(getattr(result, "assessed_path", None)),
                1 if getattr(result, "file_exists", False) else 0,
                1 if getattr(result, "file_writable", False) else 0,
                1 if getattr(result, "directory_exists", False) else 0,
                1 if getattr(result, "directory_writable", False) else 0,
                table.intern(getattr(result, "parent_directory_exists", None)),
                1 if getattr(result, "parent_directory_writable", False) else 0,
                1 if getattr(rw, "exists", False) else 0,
                1 if getattr(rw, "can_read", False) else 0,
                1 if getattr(rw, "can_write", False) else 0,
                1 if getattr(rw, "can_modify", False) else 0,
            ]
        )
    return rows


class HtmlReportBuilder:
    """Accumulates GpoResults and renders the single-file HTML report."""

    # A GPO reaching thousands of machines would bloat the payload if every DN
    # were listed, so the per-GPO list is capped and the true count kept alongside.
    MAX_LISTED_COMPUTERS = 500

    def __init__(self, domain: Optional[str] = None, command_line: Optional[str] = None, show_blob: bool = False):
        self.domain = domain or ""
        self.command_line = command_line or ""
        self.show_blob = show_blob
        self.table = StringTable()
        self.table.intern("")  # index 0

        self.gpos: List[List[Any]] = []
        # Parallel to self.gpos: serialised GpoScope, or None when unresolved.
        self.scopes: List[Any] = []
        self.setting_types: List[str] = []
        self._setting_type_index: Dict[str, int] = {}

        # Columnar finding storage.
        self.f_gpo: List[int] = []
        self.f_type: List[int] = []
        self.f_policy: List[int] = []
        self.f_triage: List[int] = []
        self.f_reason: List[int] = []
        self.f_detail: List[int] = []
        self.f_source: List[int] = []
        self.f_fields: List[List[List[int]]] = []
        self.f_aces: List[List[List[int]]] = []
        self.f_paths: List[List[List[int]]] = []
        self.f_has: List[int] = []  # 1 = real finding, 0 = setting with no finding
        # PORT ADDITION: index into the help KB, or -1. See view/finding_help.py.
        self.f_help: List[int] = []

    # -- ingest ---------------------------------------------------------------

    def _setting_type(self, name: str) -> int:
        existing = self._setting_type_index.get(name)
        if existing is not None:
            return existing
        index = len(self.setting_types)
        self.setting_types.append(name)
        self._setting_type_index[name] = index
        return index

    def _scope_row(self, scope) -> Optional[List[Any]]:
        """Serialise a GpoScope for the report, or None if scope was not resolved."""
        if scope is None:
            return None
        table = self.table
        computers = list(scope.affected_computers or [])
        listed = computers[: self.MAX_LISTED_COMPUTERS]
        return [
            len(computers),
            1 if scope.is_orphaned else 0,
            1 if scope.all_links_disabled else 0,
            1 if scope.enforced_anywhere else 0,
            1 if scope.security_filtering_narrowed else 0,
            table.intern(scope.wmi_filter),
            [table.intern(dn) for dn in listed],
            [table.intern(note) for note in (scope.notes or [])],
            [
                [table.intern(link.container_dn), table.intern(link.status_text)]
                for link in (scope.links or [])
            ],
            [
                table.intern(t.display_name or t.sid or "")
                for t in (scope.security_filter_principals or [])
            ],
            len(scope.affected_users or []),
        ]

    def add_gpo_result(self, gpo_result, scope=None) -> None:
        """Ingest one GpoResult, including its settings that produced no findings.

        `scope` is an optional GpoScope describing which computers the GPO reaches;
        it drives the reach facets and the scope section of the detail pane.
        """
        attributes = gpo_result.attributes
        table = self.table

        links = [
            [table.intern(link.link_path), table.intern(link.link_enforced)]
            for link in (attributes.gpo_links or [])
        ]
        gpo_index = len(self.gpos)
        self.scopes.append(self._scope_row(scope))
        self.gpos.append(
            [
                table.intern(attributes.display_name),
                table.intern(attributes.uid),
                table.intern(attributes.path_in_sysvol),
                table.intern(attributes.distinguished_name),
                table.intern(attributes.version_number),
                1 if attributes.computer_policy_enabled else 0,
                1 if attributes.user_policy_enabled else 0,
                1 if attributes.is_morphed_gpo else 0,
                table.intern(
                    attributes.created_date.isoformat()
                    if attributes.created_date
                    else None
                ),
                table.intern(
                    attributes.modified_date.isoformat()
                    if attributes.modified_date
                    else None
                ),
                links,
            ]
        )

        # GPO-level findings (the nTSecurityDescriptor ACL finding).
        for finding in gpo_result.gpo_attribute_findings or []:
            self._add_row(
                gpo_index=gpo_index,
                type_name="GPO Attributes",
                policy=3,
                finding=finding,
                setting=None,
                has_finding=1,
            )

        for setting_result in gpo_result.setting_results or []:
            setting = setting_result.setting
            type_name = type(setting).__name__ if setting is not None else "Unknown"
            policy = self._policy_code(setting)
            if setting_result.findings:
                for finding in setting_result.findings:
                    self._add_row(
                        gpo_index=gpo_index,
                        type_name=type_name,
                        policy=policy,
                        finding=finding,
                        setting=setting,
                        has_finding=1,
                    )
            else:
                # Settings with no finding are kept so the HTML carries the same
                # information as the default `nice` report, behind a filter toggle.
                self._add_row(
                    gpo_index=gpo_index,
                    type_name=type_name,
                    policy=policy,
                    finding=None,
                    setting=setting,
                    has_finding=0,
                )

    @staticmethod
    def _policy_code(setting) -> int:
        policy_type = getattr(setting, "policy_type", None)
        name = getattr(policy_type, "name", None)
        return {"Computer": 0, "User": 1, "Package": 2}.get(name, 3)

    def _add_row(
        self,
        gpo_index: int,
        type_name: str,
        policy: int,
        finding,
        setting,
        has_finding: int,
    ) -> None:
        table = self.table
        self.f_gpo.append(gpo_index)
        self.f_type.append(self._setting_type(type_name))
        self.f_policy.append(policy)
        self.f_triage.append(int(finding.triage) if finding is not None else -1)
        self.f_reason.append(table.intern(finding.finding_reason if finding else None))
        self.f_detail.append(table.intern(finding.finding_detail if finding else None))
        self.f_source.append(table.intern(getattr(setting, "source", None)))

        pairs = _flatten(setting) if setting is not None else []
        if not getattr(self, "show_blob", False):
            # Keep the report compact by default: value_string already holds the
            # 2-line preview, and value_bytes would inline the full blob hex.
            pairs = [(k, v) for k, v in pairs if not k.endswith("value_bytes")]
        self.f_fields.append(
            [[table.intern(key), table.intern(value)] for key, value in pairs]
        )
        self.f_aces.append(
            _ace_rows(getattr(finding, "acl_result", None), table) if finding else []
        )
        self.f_paths.append(
            _path_rows(getattr(finding, "path_findings", None), table) if finding else []
        )
        self.f_has.append(has_finding)
        slug = lookup_slug(finding.finding_reason if finding else None)
        self.f_help.append(_HELP_ORDER.get(slug, -1) if slug else -1)

    # -- render ---------------------------------------------------------------

    def build_payload(self) -> Dict[str, Any]:
        counts = {name: 0 for name in ("Green", "Yellow", "Red", "Black")}
        for value in self.f_triage:
            if value >= 0:
                counts[Triage(value).name] += 1

        return {
            "meta": {
                "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "domain": self.domain,
                "commandLine": self.command_line,
                "gpoCount": len(self.gpos),
                "rowCount": len(self.f_gpo),
                "findingCount": sum(self.f_has),
                "triageCounts": counts,
                "scopeResolved": any(row is not None for row in self.scopes),
                "maxListedComputers": self.MAX_LISTED_COMPUTERS,
            },
            "helpEntries": entries_for_payload(),
            "strings": self.table.strings,
            "settingTypes": self.setting_types,
            "gpos": self.gpos,
            "scopes": self.scopes,
            "findings": {
                "gpo": self.f_gpo,
                "type": self.f_type,
                "policy": self.f_policy,
                "triage": self.f_triage,
                "reason": self.f_reason,
                "detail": self.f_detail,
                "source": self.f_source,
                "fields": self.f_fields,
                "aces": self.f_aces,
                "paths": self.f_paths,
                "has": self.f_has,
                "help": self.f_help,
            },
        }

    def render(self) -> str:
        payload = self.build_payload()
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        packed = base64.b64encode(gzip.compress(raw, 9)).decode("ascii")

        template_path = os.path.join(os.path.dirname(__file__), _TEMPLATE_NAME)
        with open(template_path, "r", encoding="utf-8") as handle:
            template = handle.read()

        summary = payload["meta"]
        return (
            template.replace("__GROUP3R_DATA__", packed)
            .replace("__GROUP3R_RAW_BYTES__", str(len(raw)))
            .replace("__GROUP3R_TITLE__", html.escape(self.domain or "Group3r report"))
        ), summary

    def write(self, path: str) -> Dict[str, Any]:
        markup, summary = self.render()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markup)
        summary = dict(summary)
        summary["outputPath"] = path
        summary["outputBytes"] = os.path.getsize(path)
        return summary
