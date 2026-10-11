"""Port of Group3r/Group3rRunner.cs and Group3r/Group3r.cs

Sets everything up and runs the message-processing loop. The only addition is the
`--html` hook at the end, which writes the filterable HTML report from the
GpoResults that GroupCon collected; the `nice` and `json` printers are untouched.
"""

import sys
import threading
from typing import List, Optional

from .concurrency.grouper_mq import GrouperMq
from .concurrency.messages import QueueMessage
from .group_con import GroupCon
from .logging_setup import setup_logger
from .options import options_parser
from .view.banner import print_banner
from .view.message_processor import CliMessageProcessor

# The original guards console writes with a lock because the Mq consumer and the
# banner both write to stdout.
_console_writer_lock = threading.Lock()


class Group3rRunner:
    """Port of Group3r.Group3rRunner."""

    def run(self, args: List[str]) -> int:
        with _console_writer_lock:
            print_banner()

        mq = GrouperMq()

        try:
            options = options_parser.parse(args, mq)
            if options is None:
                return 0

            setup_logger(
                options.log_to_file,
                options.log_to_console,
                mq,
                options.log_level_string,
                options.log_file_path,
            )

            controller = GroupCon(options, mq)
            group_con_thread = threading.Thread(
                target=controller.execute, name="GroupCon", daemon=True
            )
            group_con_thread.start()

            self.handle_forever(options, mq)

            # ADDITION: emit the filterable HTML report once analysis is done.
            self._write_html_report(options, controller, mq)
            self._write_bloodhound_export(options, controller, mq)
            return 0
        except Exception as exc:  # noqa: BLE001 - mirrors the C# catch-all
            sys.stdout.write(
                "Unhandled exception in Group3rRunner. Please report the following "
                "error directly to l0ss or file an issue in GitHub:\n"
            )
            sys.stdout.write(str(exc) + "\n")
            self.dump_queue(mq)
            return 1

    def dump_queue(self, mq: GrouperMq) -> None:
        """Port of Group3rRunner.DumpQueue.

        Prints the Mq and exits on fatal error.
        """
        while True:
            message = mq.try_take()
            if message is None:
                break
            with _console_writer_lock:
                # emergency dump of queue contents to console
                sys.stdout.write(message.get_message() + "\n")
        if sys.gettrace() is not None:  # Debugger.IsAttached
            with _console_writer_lock:
                sys.stdout.write("Emergency quit, dumped queue to console.\n")
        # TODO: exit nicely by returning to calling context.

    def handle_forever(self, options, mq: GrouperMq) -> None:
        """Port of Group3rRunner.HandleForever."""
        # TODO: Implement option for output type when required.
        processor = CliMessageProcessor()

        exit_flag = False
        while exit_flag is False:
            # mq.Pop blocks.
            message: QueueMessage = mq.pop()
            with _console_writer_lock:
                exit_flag = processor.process_message(message, options)

    def _write_html_report(self, options, controller: GroupCon, mq: GrouperMq) -> None:
        """ADDITION: not part of the original tool.

        Builds the single-file filterable HTML report from every GpoResult the
        controller accumulated. Failures here are reported but never allowed to
        mask a completed scan -- the default reports have already been emitted by
        this point.
        """
        html_path: Optional[str] = getattr(options, "html_path", None)
        if not html_path:
            return

        try:
            from .view.html_report import HtmlReportBuilder

            builder = HtmlReportBuilder(
                domain=getattr(options, "target_domain", None)
                or getattr(options, "sysvol_path", None)
                or "",
                command_line=" ".join(sys.argv[1:]),
                show_blob=getattr(options, "show_blob", False),
            )
            scopes = getattr(controller, "scopes", {}) or {}
            for gpo_result in controller.gpo_results:
                guid = (gpo_result.attributes.uid or "").upper()
                builder.add_gpo_result(gpo_result, scope=scopes.get(guid))

            summary = builder.write(html_path)
            sys.stdout.write(
                "Wrote HTML report to {path} ({size:.1f} MB, {gpos} GPOs, "
                "{findings} findings, {rows} rows)\n".format(
                    path=summary["outputPath"],
                    size=summary["outputBytes"] / (1024 * 1024),
                    gpos=summary["gpoCount"],
                    findings=summary["findingCount"],
                    rows=summary["rowCount"],
                )
            )
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write("Failed to write HTML report: " + str(exc) + "\n")


    def _write_bloodhound_export(self, options, controller: GroupCon, mq: GrouperMq) -> None:
        """ADDITION: not part of the original tool.

        Writes reviewable BloodHound edge files derived from GPO settings and the
        resolved scope. Deliberately writes files rather than mutating a Neo4j
        database, so the operator can read the queries before running them.
        """
        prefix: Optional[str] = getattr(options, "bloodhound_path", None)
        if not prefix:
            return

        scopes = getattr(controller, "scopes", {}) or {}
        if not scopes:
            sys.stdout.write(
                "Skipping BloodHound export: no GPO scope was resolved, so there is "
                "no way to know which computers an edge would target.\n"
            )
            return

        try:
            from .view.bloodhound_export import export

            summary = export(
                controller.gpo_results,
                scopes,
                prefix,
                domain=getattr(options, "target_domain", None),
            )
            counts = ", ".join(
                f"{kind}={count}" for kind, count in sorted(
                    (summary.get("edge_counts") or {}).items()
                )
            )
            sys.stdout.write(
                "Wrote BloodHound export: "
                + ", ".join(summary.get("files", []))
                + (f" ({counts})" if counts else "")
                + "\n"
            )
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write("Failed to write BloodHound export: " + str(exc) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    """Port of Group3r.Main."""
    args = list(sys.argv[1:] if argv is None else argv)
    return Group3rRunner().run(args)
