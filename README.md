# PyGroup3r

A Python port of [Group3r](https://github.com/Group3r/Group3r) — the Group Policy
auditing tool by @mikeloss — that authenticates with **impacket** so it runs from
Linux, plus a filterable single-file **HTML report** on top of the original output
formats.

The goal is *identical findings*: the same finding reasons, details, triage levels
and suppression behaviour as the C# original, from the same GPO data. 

![The HTML report](docs/img/report-overview.png)

**[See a full example report](example-report.html)** — download and open it
locally; GitHub serves HTML as plain text. 

## Why

Group3r is excellent but assumes a domain-joined Windows host. This port targets
the common engagement setup — a Linux box with credentials — and addresses the
practical problem that its text reports reach hundreds of megabytes in large
environments, which is effectively unsearchable.

## Install

```bash
pipx install git+https://github.com/magev0/PyGroup3r.git
# run it with:
pygroup3r -h
# upgrade later with:
pipx upgrade pygroup3r
```

Python 3.12+. Runtime dependencies are impacket and pycryptodomex only; the HTML
report has **no** external dependencies at all.

## Usage

```bash
# Online, password auth, with the HTML report
python3 -m group3rpy -d corp.local --username jbloggs -p 'Passw0rd!' \
    --dc-ip 10.0.0.10 -s --html report.html

# Pass-the-hash
python3 -m group3rpy -d corp.local --username jbloggs \
    -H :2b576acbe6bcfda7294d6bd18041b8fe --dc-ip 10.0.0.10 -s

# Kerberos from an existing ccache
export KRB5CCNAME=jbloggs.ccache
python3 -m group3rpy -d corp.local -k --dc-ip 10.0.0.10 -s

# With blast-radius resolution and a BloodHound edge export
python3 -m group3rpy -d corp.local --username jbloggs -p 'Passw0rd!' \
    --dc-ip 10.0.0.10 -s --scope --html report.html --bloodhound edges

# Offline against a SYSVOL copy (no DC needed)
python3 -m group3rpy -o -y /mnt/sysvol -s --html report.html

# Only findings, Red and above, to a file
python3 -m group3rpy -d corp.local --username jbloggs -p 'Passw0rd!' \
    -w -a 3 -f group3r.txt
```

### Options

Everything from the original is preserved verbatim, including flag letters and
the `--verobsity` spelling. Run `-h` for the full list. Original flags:

| Flag | Meaning |
|---|---|
| `-c`, `--dc` | Target domain controller |
| `-d`, `--domain` | Domain to query |
| `-o`, `--offline` | No LDAP/SMB; requires `-y` |
| `-y`, `--sysvol` | Path to a SYSVOL directory |
| `-f`, `--outfile` | Output file |
| `-s`, `--stdout` | Stream results to stdout |
| `-t`, `--threads` | Max threads |
| `-v`, `--verobsity` | `info`, `debug`, `degub`, `trace` |
| `-r`, `--currentonly` | Skip `Policies_NTFRS_*` replication leftovers |
| `-w`, `--findingsonly` | Only settings that produced a finding |
| `-a`, `--mintriage` | Minimum severity, 1–4 |
| `-u`, `--testuser` | Focus permission checks on `domain\user` |
| `-e`, `--enabled` | Only enabled policy types and settings |

Additions for this port:

| Flag | Meaning |
|---|---|
| `--username` | Username (the original inherits the Windows logon session) |
| `-p`, `--password` | Password |
| `-H`, `--hashes` | `LMHASH:NTHASH` |
| `-k`, `--kerberos` | Kerberos, from `KRB5CCNAME` if no credentials given |
| `--aes-key` | Kerberos AES key |
| `--dc-ip` | DC address, when it differs from the domain name |
| `--html` | Write the filterable HTML report |
| `--scope` | Resolve which computers each GPO actually applies to |
| `--scope-users` | Also enumerate affected users (implies `--scope`; slow on a big domain) |
| `--bloodhound` | Write BloodHound edge export (implies `--scope`) |

> `-u` keeps its original meaning (`--testuser`), so the username flag is
> long-only rather than impacket's usual `-u`.

## The HTML report

Every finding carries a *what this is / how it is abused / how to fix it*
block, and the ACL table flags ACEs that hand write-equivalent control to a
principal that is not already domain-privileged:

![Finding guidance](docs/img/report-guidance.png)


`--html report.html` writes one self-contained file — no external scripts, styles
or fonts, so it is safe to hand to a client and works offline.

**Filtering**
- Triage pills (Black / Red / Yellow / Green, plus *None* for settings with no
  finding)
- Facets for finding type, policy scope (Computer / User / Package) and GPO, each
  with counts and a search box for the GPO list
- Sortable columns
- Export the current filtered set to CSV or JSON

**Search** supports more than substrings:

| Query | Meaning |
|---|---|
| `cpassword` | free text across every field |
| `"Domain Users"` | exact phrase |
| `-Green` | exclude |
| `type:SchedTask` | scope to a field |
| `trustee:"Domain Users"` | ACL trustee or SID |
| `right:GENERIC_WRITE` | ACL right |
| `path:netlogon` | assessed path |
| `key:`, `value:`, `gpo:`, `reason:`, `detail:`, `source:` | other scopes |

Multiple terms are ANDed. `/` focuses search, `j`/`k` move, `Esc` closes the
detail pane. The page follows the OS light/dark setting.

**Why it stays fast and small.** Strings are interned so each distinct finding
reason is stored once; filterable fields live in parallel integer arrays; the
payload is gzipped and inflated in the browser; and rows are virtualised so the
DOM holds only what is on screen. Search is evaluated against the interned string
*dictionary* rather than the rows, so its cost scales with vocabulary size, not
finding count. In practice this is roughly **6 bytes per finding row**, so a
report that runs to hundreds of MB as flat text lands in the low single-digit MB.

## Blast radius (`--scope`)

Group3r tells you a GPO is linked to `OU=Workstations,DC=corp,DC=local`. It never
tells you that this means 412 specific servers — or nothing at all. That
distinction is most of triage: a Black finding on an unlinked GPO is noise.

`--scope` resolves it, via LDAP:

- `gPLink` parsing including the per-link status bits (1 = disabled, 2 = enforced)
- `gPOptions` block-inheritance — which Group3r actually *requests* and then throws
  away
- enforced links, which correctly flow past a block-inheritance boundary
- the full container tree, including plain containers like `CN=Computers` that
  cannot hold a link but still inherit
- **security filtering**, via the Apply Group Policy extended right, so a GPO
  filtered to one group isn't reported as hitting every machine under its link
- **WMI filters** and **site links**, reported as "scope may be narrower" and
  "unresolved" rather than silently ignored

It deliberately does **not** claim precedence — which GPO *wins* for a given value
depends on link-order semantics this port does not assert. Blast radius only needs
set membership, and a wrong precedence claim would be worse than none.

In the HTML report this adds a **Reach** column, reach-bucket facets
(`1000+`, `101-1000`, …, `0 computers`, `links disabled`, `not linked`), "only
show" toggles for enforced / security-filtered / WMI-filtered, sorting by reach,
and `computer:` and `container:` search fields — so "every Red finding that
touches more than 100 machines" is two clicks. Scope also lands in the CSV and
JSON exports.

Nothing here touches the `nice` or `json` printers, so parity is unaffected.

## BloodHound export (`--bloodhound <prefix>`)

Derives attack-path edges from GPO settings, scoped to the machines each GPO
actually reaches:

- `AdminTo`, `CanRDP`, `CanPSRemote` from members added to the corresponding
  built-in local groups
- `GPOLocalGroupMember` for other privileged local groups (Backup / Print / Server
  / Account Operators, Distributed COM Users) — *not* relabelled as `AdminTo`
- `GPOGrantsPrivilege` from privilege rights, marked `adminEquivalent` where the
  ported classification table says the right is a local privesc
- `GPOServiceAccount` and `GPOScheduledTaskPrincipal` from service and task
  principals

It writes **files, not database changes**: `<prefix>.json` (OpenGraph-shaped) and
`<prefix>.cypher`. The Cypher uses `MERGE`, never `CREATE`, so re-running does not
duplicate edges; it `MATCH`es principals and computers rather than `MERGE`ing them,
so it cannot invent phantom nodes; provenance (`source='group3rpy'`, GPO guid) is
written under `ON CREATE SET` only, so the commented-out rollback query at the top
of the file cannot delete edges BloodHound genuinely collected. Read it before you
run it.

GPOs that cannot apply (orphaned, all links disabled, computer policy disabled)
produce **zero** edges. Where scope is uncertain (security or WMI filtering) edges
are still emitted but carry `uncertain: true` and a reason.

> The OpenGraph JSON schema is shaped from documentation, **not verified against a
> running BloodHound**. Check it against your version; the writer is one small
> function if it needs adjusting. The `.cypher` file does not depend on it.

## Credit

All detection logic, finding text and rule tables are the work of the Group3r
authors — [@mikeloss](https://github.com/mikeloss) and contributors — and of the
Snaffler project whose classifier engine Group3r embeds. This is a port; the
judgement about what makes a GPO misconfiguration interesting is theirs.

Upstream: https://github.com/Group3r/Group3r

## Licence

Upstream Group3r is **GPL v3** (`upstream/LICENSE`). This port is a derivative
work and is therefore also GPL v3 — including the finding text, rule tables and
detection logic it carries over. If you redistribute it, the GPL's source
requirements apply.
