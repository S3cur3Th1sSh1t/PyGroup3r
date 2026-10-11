"""Port of Group3r/View/NiceGpoPrinter.cs.

Implementation of IGpoOutputter which just returns nice GPO output.

This is the file that produces Group3r's default report, so it is a line-for-line
transcription: same tables, same column labels, same indent width, same tail
marker, same ordering, same skipped-when-blank behaviour.
"""

import sys
import xml.etree.ElementTree as ElementTree
from typing import Any, Iterator, List, Optional

from ..ad.gpo import GPO, PolicyType
from ..assessment.finding import GpoFinding, GpoResult, SettingResult, SimpleAce
from ..settings.data_source_setting import DataSourceSetting
from ..settings.device_setting import DeviceSetting
from ..settings.drive_setting import DriveSetting
from ..settings.env_var_setting import EnvVarSetting
from ..settings.event_audit_setting import EventAuditSetting
from ..settings.file_setting import FileSetting
from ..settings.folder_setting import FolderSetting
from ..settings.group_setting import GroupSetting
from ..settings.ini_file_setting import IniFileSetting
from ..settings.kerb_policy_setting import KerbPolicySetting
from ..settings.net_option_setting import NetOptionSetting
from ..settings.network_share_setting import NetworkShareSetting
from ..settings.nt_service_setting import NtServiceSetting
from ..settings.package_setting import PackageSetting
from ..settings.printer_setting import PrinterSetting
from ..settings.priv_right_setting import PrivRightSetting
from ..settings.registry_setting import RegistrySetting
from ..settings.sched_task_setting import (
    SchedTaskEmailAction,
    SchedTaskExecAction,
    SchedTaskSetting,
    SchedTaskShowMessageAction,
)
from ..settings.script_setting import ScriptSetting
from ..settings.shortcut_setting import ShortcutSetting
from ..settings.system_access_setting import SystemAccessSetting
from ..settings.user_setting import UserSetting
from .console_tables import ConsoleTable, dotnet_str, net_format
from .gpo_printer import IGpoPrinter

# PORT NOTE: Environment.NewLine / StringBuilder.AppendLine on the Windows box
# the original runs on. IndentPara depends on the report being CRLF-delimited.
NEWLINE = "\r\n"

# PORT NOTE: .NET renders `default(Guid)` (Guid.Empty) like this. PackageSetting
# holds ProductCode/UpgradeProductCode as a non-nullable Guid in C#, but as
# `uuid.UUID | None` in this port, so a missing code has to render as the same
# text `Guid.Empty.ToString()` would produce.
EMPTY_GUID = "00000000-0000-0000-0000-000000000000"


def _is_null_or_white_space(value: Optional[str]) -> bool:
    """PORT NOTE: `String.IsNullOrWhiteSpace`."""
    return value is None or value.strip() == ""


def _inner_xml(node: Any) -> str:
    """PORT NOTE: `XmlNode.InnerXml`. The sched task parsers hand over
    xml.etree Elements (see settings/sched_task_setting.py), so the markup of the
    node's children has to be re-serialised here."""
    if isinstance(node, str):
        return node
    text = node.text or ""
    return text + "".join(ElementTree.tostring(child, encoding="unicode") for child in node)


class NiceGpoPrinter(IGpoPrinter):
    """Implementation of IGpoOutputter which just returns nice GPO output."""

    def __init__(self, options):
        """Summary: constructor
        Arguments: none
        Returns: NiceGpoPrinter instance
        """
        self.grouper_options = options
        self._indent = 4
        # set up the printer

    def output_gpo(self, gpo: GPO) -> str:
        """Summary: Implementation of OutputGPO which returns the GPO as a nice string.
        Arguments: GPO object to be outputted
        Returns: string representation of GPO
        """
        gpo_string = ""
        return gpo_string

    def output_gpo_result(self, gpo_result: GpoResult) -> str:
        if self.grouper_options.current_pol_only and gpo_result.attributes.is_morphed_gpo:
            return ""
        # bail out entirely if both pol types are disabled and we are running with the -e flag.
        if self.grouper_options.enabled_pol_only is True:
            if (
                not gpo_result.attributes.computer_policy_enabled
                and not gpo_result.attributes.user_policy_enabled
            ):
                return ""

        #
        # GPO NAME AND ATTRIBUTES
        #

        sb: List[str] = []
        sb.append(NEWLINE)
        morphed = "Current"
        if gpo_result.attributes.is_morphed_gpo:
            morphed = "Morphed"
        gpo_display_name = gpo_result.attributes.display_name
        if _is_null_or_white_space(gpo_display_name):
            gpo_display_name = "(No Display Name)"
        columntwo = net_format("{0} {1} {2}", gpo_display_name, gpo_result.attributes.uid, morphed)
        gpo_table = ConsoleTable("GPO", columntwo)
        gpo_table.add_row("Date Created", gpo_result.attributes.created_date)
        gpo_table.add_row("Date Modified", gpo_result.attributes.modified_date)
        gpo_table.add_row("Path in SYSVOL", gpo_result.attributes.path_in_sysvol)

        computer_policy = "Disabled"
        user_policy = "Disabled"
        if gpo_result.attributes.computer_policy_enabled:
            computer_policy = "Enabled"
        if gpo_result.attributes.user_policy_enabled:
            user_policy = "Enabled"

        gpo_table.add_row("Computer Policy", computer_policy)
        gpo_table.add_row("User Policy", user_policy)

        # if there are links, add them
        if len(gpo_result.attributes.gpo_links) >= 1:
            linkenabled = False
            for gpo_link in gpo_result.attributes.gpo_links:
                link_path = net_format("{0} ({1})", gpo_link.link_path, gpo_link.link_enforced)
                # if at least one link isn't enabled...
                if "Enabled" in gpo_link.link_enforced:
                    linkenabled = True
                gpo_table.add_row("Link", link_path)
            # and we're only showing enabled policies...
            if not linkenabled and self.grouper_options.enabled_pol_only:
                # bail out.
                return ""
        else:
            # if there aren't any, and we're only showing enabled policy, bail out.
            if self.grouper_options.enabled_pol_only:
                return ""

        sb.append(gpo_table.to_mark_down_string())
        #
        # Findings for GPO Attributes
        #

        # gpoFindingTable = ConsoleTable("Finding", "Placeholder")
        # gpoFindingTable.AddRow("This is where", "Findings about GPO ACLs will go.")
        # sb.Append(IndentPara(gpoFindingTable.ToMarkDownString(), 1))
        # sb.AppendLine("Findings for GPO Attributes will go here.")
        #
        # if (gpoResult.GpoAttributeFindings.Count >= 1)
        # {
        #     foreach (GpoFinding finding in gpoResult.GpoAttributeFindings)
        #     {
        #         sb.Append(PrintNiceFinding(finding));
        #     }
        # }
        #
        # sb.AppendLine("-------------------------------");
        # sb.AppendLine("ACL Findings for GPO will go here.");
        # if (gpoResult.GpoAclResult.Count >= 1)
        # {
        #     sb.AppendLine(PrintNiceAces(gpoResult.GpoAclResult));
        # }
        # sb.AppendLine("-------------------------------");
        #
        for sr in gpo_result.setting_results:
            if (len(sr.findings) == 0) and self.grouper_options.findings_only:
                continue

            setting_morphed = ""
            if sr.setting.is_morphed:
                if self.grouper_options.current_pol_only:
                    # bail out because this is a morphed setting.
                    continue
                setting_morphed = " - Morphed"

            poltype = ""

            if sr.setting.policy_type == PolicyType.Computer:
                # if computer policy is disabled on this GPO, skip it.
                if (
                    self.grouper_options.enabled_pol_only
                    and not gpo_result.attributes.computer_policy_enabled
                ):
                    continue
                poltype = "Computer Policy" + setting_morphed
            elif sr.setting.policy_type == PolicyType.User:
                if (
                    self.grouper_options.enabled_pol_only
                    and not gpo_result.attributes.user_policy_enabled
                ):
                    continue
                poltype = "User Policy" + setting_morphed
            elif sr.setting.policy_type == PolicyType.Package:
                poltype = "Package Policy" + setting_morphed

            # big ol' list of output formatters that should be their own methods but i'm a MANIAC AND YOU CAN'T STOP ME!
            if type(sr.setting) is DataSourceSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Data Source")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "Description", cs.description)
                s_table = self.table_add(s_table, "Driver", cs.driver)
                s_table = self.table_add(s_table, "UserName", cs.user_name)
                s_table = self.table_add(s_table, "Cpassword", cs.cpassword)
                s_table = self.table_add(s_table, "Password", cs.dsn)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is DeviceSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Devices")
                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is DriveSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Drive")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "Path", cs.path)
                s_table = self.table_add(s_table, "Label", cs.label)
                s_table = self.table_add(s_table, "UserName", cs.user_name)
                s_table = self.table_add(s_table, "Cpassword", cs.cpassword)
                s_table = self.table_add(s_table, "Password", cs.password)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))

            elif type(sr.setting) is EnvVarSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Env Variable")
                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is EventAuditSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Audit Policy")
                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is FileSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "File")

                s_table = self.table_add(s_table, "Action", cs.file_action)
                s_table = self.table_add(s_table, "FileName", cs.file_name)
                s_table = self.table_add(s_table, "FromPath", cs.from_path)
                s_table = self.table_add(s_table, "TargetPath", cs.target_path)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is FolderSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Folder")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is GroupSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Group")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "NewName", cs.new_name)
                s_table = self.table_add(s_table, "Delete All Groups", dotnet_str(cs.delete_all_groups))
                s_table = self.table_add(s_table, "Delete All Users", dotnet_str(cs.delete_all_users))
                s_table = self.table_add(s_table, "Remove Accounts", dotnet_str(cs.remove_accounts))

                for member in cs.members:
                    memberstring = (
                        dotnet_str(member.action)
                        + " "
                        + dotnet_str(member.name)
                        + " "
                        + dotnet_str(member.resolved_name)
                        + " "
                        + dotnet_str(member.sid)
                    )

                    s_table = self.table_add(s_table, "Member", memberstring)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))

            elif type(sr.setting) is IniFileSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Ini File")

                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")
                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is KerbPolicySetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Kerberos Policy")

                s_table = self.table_add(s_table, cs.key, cs.value)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is NetOptionSetting:
                cs = sr.setting
                s_table = ConsoleTable("Setting - " + poltype, "Network Options")

                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is NetworkShareSetting:
                cs = sr.setting
                s_table = ConsoleTable("Setting - " + poltype, "Network Share")

                s_table = self.table_add(s_table, "No Output Formatter For This Setting Type", "")

                # sTable = TableAdd(sTable, "Action", cs.FileAction);

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is NtServiceSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Service")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Service Name", cs.service_name)
                if cs.startup_type is not None:
                    startup_type = ""
                    if cs.startup_type == "0":
                        startup_type = "Boot"
                    elif cs.startup_type == "1":
                        startup_type = "System"
                    elif cs.startup_type == "2":
                        startup_type = "Automatic"
                    elif cs.startup_type == "3":
                        startup_type = "Manual"
                    elif cs.startup_type == "4":
                        startup_type = "Disabled"

                    s_table = self.table_add(s_table, "Startup Type", startup_type)

                # sTable = TableAdd(sTable, "Sddl", cs.Sddl);
                s_table = self.table_add(s_table, "Program", cs.program)
                s_table = self.table_add(s_table, "Args", cs.args)
                s_table = self.table_add(s_table, "UserName", cs.user_name)
                s_table = self.table_add(s_table, "Cpassword", cs.cpassword)
                s_table = self.table_add(s_table, "Password", cs.password)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is PackageSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Package")

                s_table = self.table_add(s_table, "Display Name", cs.display_name)
                s_table = self.table_add(s_table, "CreatedDate", dotnet_str(cs.created_date))
                s_table = self.table_add(s_table, "Action", cs.package_action)

                for file in cs.msi_file_list:
                    s_table = self.table_add(s_table, "File", file)
                # PORT NOTE: see EMPTY_GUID - these two are non-nullable Guids in
                # the C#, so a missing code renders as Guid.Empty would.
                s_table = self.table_add(
                    s_table,
                    "Product Code",
                    EMPTY_GUID if cs.product_code is None else dotnet_str(cs.product_code),
                )
                s_table = self.table_add(
                    s_table,
                    "Upgrade Product Code",
                    EMPTY_GUID if cs.upgrade_product_code is None else dotnet_str(cs.upgrade_product_code),
                )

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is PrinterSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Printer")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "Comment", cs.comment)
                s_table = self.table_add(s_table, "Path", cs.path)
                s_table = self.table_add(s_table, "UserName", cs.user_name)
                s_table = self.table_add(s_table, "Cpassword", cs.cpassword)
                s_table = self.table_add(s_table, "Password", cs.password)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is PrivRightSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "User Rights Assignment")

                s_table = self.table_add(s_table, "Privilege Name", cs.privilege)

                first = True
                t = "Trustee"
                for trustee in cs.trustees:
                    if first:
                        first = False
                    else:
                        t = ""
                    if trustee.display_name == "Failed to resolve SID.":
                        s_table = self.table_add(s_table, t, trustee.sid)
                    else:
                        s_table = self.table_add(
                            s_table, t, dotnet_str(trustee.display_name) + " " + dotnet_str(trustee.sid)
                        )
                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is RegistrySetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Registry")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "Key", dotnet_str(cs.hive) + "\\" + dotnet_str(cs.key))

                for value in cs.values:
                    s_table = self.table_add(s_table, "Value Name", value.value_name)
                    s_table = self.table_add(s_table, "Value Type", dotnet_str(value.reg_key_val_type))
                    s_table = self.table_add(s_table, "Value String", self._registry_value_display(value))

                # PORT NOTE: the C# has a stray `Console.WriteLine(sTable.ToMarkDownString());`
                # here, which dumps every registry table to the console a second
                # time, on top of the copy that goes into the report. Kept, because
                # dropping it would change what the console shows.
                sys.stdout.write(s_table.to_mark_down_string() + NEWLINE)
                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is SchedTaskSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Scheduled Task")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Task Type", dotnet_str(cs.task_type))
                s_table = self.table_add(s_table, "Description", cs.description1)
                s_table = self.table_add(s_table, "Enabled", dotnet_str(cs.enabled))
                s_table = self.table_add(s_table, "Name", cs.name)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))

                if len(cs.principals) >= 1:
                    i = 1
                    for principal in cs.principals:
                        p_table = ConsoleTable("Principal", dotnet_str(i))
                        p_table = self.table_add(p_table, "Id", principal.id)
                        p_table = self.table_add(p_table, "UserID", principal.user_id)
                        p_table = self.table_add(p_table, "Cpassword", principal.cpassword)
                        p_table = self.table_add(p_table, "Password", principal.password)
                        p_table = self.table_add(p_table, "LogonType", principal.logon_type)
                        p_table = self.table_add(p_table, "RunLevel", principal.run_level)
                        sb.append(self.indent_para(p_table.to_mark_down_string(), 2))
                        i += 1

                if len(cs.actions) >= 1:
                    for action in cs.actions:
                        if type(action) is SchedTaskEmailAction:
                            ca = action

                            a_table = ConsoleTable("Email Action", "")
                            a_table = self.table_add(a_table, "From", ca.from_)
                            a_table = self.table_add(a_table, "To", ca.to)
                            a_table = self.table_add(a_table, "Subject", ca.subject)
                            a_table = self.table_add(a_table, "Body", ca.body)
                            a_table = self.table_add(a_table, "Header Fields", ca.header_fields)
                            a_table = self.table_add(a_table, "Server", ca.server)
                            if len(ca.attachments) >= 1:
                                for attachment in ca.attachments:
                                    a_table = self.table_add(a_table, "Attachment", attachment)
                            sb.append(self.indent_para(a_table.to_mark_down_string(), 2))
                        elif type(action) is SchedTaskExecAction:
                            ca = action

                            a_table = ConsoleTable("Execute Action", "")
                            s_table = self.table_add(a_table, "Command", ca.command)
                            s_table = self.table_add(a_table, "Args", ca.args)
                            s_table = self.table_add(a_table, "Working Directory", ca.working_dir)

                            sb.append(self.indent_para(a_table.to_mark_down_string(), 2))
                        elif type(action) is SchedTaskShowMessageAction:
                            ca = action

                            a_table = ConsoleTable("Message Action", "")

                            s_table = self.table_add(a_table, "Title", ca.title)
                            s_table = self.table_add(a_table, "Body", ca.body)
                            sb.append(self.indent_para(a_table.to_mark_down_string(), 2))

                if len(cs.triggers) >= 1:
                    t_table = ConsoleTable("Triggers", "")
                    for node in cs.triggers:
                        t_table = self.table_add(t_table, "", _inner_xml(node))

                    sb.append(self.indent_para(t_table.to_mark_down_string(), 2))
            elif type(sr.setting) is ScriptSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Script")

                s_table = self.table_add(s_table, "Script Type", dotnet_str(cs.script_type))
                s_table = self.table_add(s_table, "CmdLine", cs.cmd_line)
                s_table = self.table_add(s_table, "Args", cs.parameters)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is ShortcutSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "Shortcut")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "Comment", cs.comment)
                s_table = self.table_add(s_table, "Shortcut Path", cs.shortcut_path)
                s_table = self.table_add(s_table, "Target Type", cs.target_type)
                s_table = self.table_add(s_table, "Target Path", cs.target_path)
                s_table = self.table_add(s_table, "Arguments", cs.arguments)
                s_table = self.table_add(s_table, "IconPath", cs.icon_path)
                s_table = self.table_add(s_table, "IconIndex", cs.icon_index)
                s_table = self.table_add(s_table, "Status", cs.status)

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            elif type(sr.setting) is SystemAccessSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "System Access")
                s_table = self.table_add(s_table, cs.setting_name, cs.value_string)
                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))

            elif type(sr.setting) is UserSetting:
                cs = sr.setting

                s_table = ConsoleTable("Setting - " + poltype, "User")

                s_table = self.table_add(s_table, "Name", cs.name)
                s_table = self.table_add(s_table, "Action", dotnet_str(cs.action))
                s_table = self.table_add(s_table, "UserName", cs.user_name)
                s_table = self.table_add(s_table, "NewName", cs.new_name)
                s_table = self.table_add(s_table, "FullName", cs.full_name)
                s_table = self.table_add(s_table, "Description", cs.description)
                s_table = self.table_add(s_table, "Cpassword", cs.cpassword)
                s_table = self.table_add(s_table, "Password", cs.password)
                s_table = self.table_add(s_table, "PwNeverExpires", dotnet_str(cs.pw_never_expires))

                sb.append(self.indent_para(s_table.to_mark_down_string(), 1))
            else:
                # PORT NOTE: C# prints `sr.Setting.GetType().ToString()`, i.e. the
                # namespace-qualified type name; the Python class name is the
                # closest equivalent.
                raise NotImplementedError(
                    "Trying to output a setting type with no output formatter: "
                    + type(sr.setting).__name__
                )

            if len(sr.findings) >= 1:
                for finding in sr.findings:
                    sb.append(self.print_nice_finding(finding))

            sb.append(NEWLINE)
        return "".join(sb)

    def print_nice_finding(self, finding: GpoFinding) -> str:
        sb: List[str] = []

        f_table = ConsoleTable("Finding", dotnet_str(finding.triage))

        f_table = self.table_add(f_table, "Reason", finding.finding_reason)
        f_table = self.table_add(f_table, "Detail", finding.finding_detail)

        sb.append(self.indent_para(f_table.to_mark_down_string(), 2))

        #
        # if (finding.AclResult.Count >= 1)
        # {
        #     sb.AppendLine("...ACL.Finding.Details...");
        #     sb.AppendLine(PrintNiceAces(finding.AclResult));
        #     sb.AppendLine("......");
        # }
        #

        #
        # if (finding.PathFindings.Count >= 1)
        # {
        #     sb.AppendLine("...Path.Finding.Details...");
        #     sb.AppendLine(PrintNicePathFindings(finding.PathFindings));
        #     sb.AppendLine("......");
        # }
        #

        return "".join(sb)

    @staticmethod
    def chunks_upto(str_: str, max_chunk_size: int) -> Iterator[str]:
        for i in range(0, len(str_), max_chunk_size):
            yield str_[i : i + min(max_chunk_size, len(str_) - i)]

    def _registry_value_display(self, value) -> Optional[str]:
        """Compact REG_BINARY preview by default, full hex with -b/--show-blob.

        Parse time always stores the compact preview in value_string and the
        raw bytes in value_bytes; expanding here keeps stdout, -f and --html
        consistent behind the same flag.
        """
        if getattr(self.grouper_options, "show_blob", False):
            raw = getattr(value, "value_bytes", None)
            if raw:
                return f"<binary, {len(raw)} bytes> {bytes(raw).hex()}"
        return value.value_string

    def table_add(self, table: ConsoleTable, v1: Optional[str], v2: Optional[str]) -> ConsoleTable:
        if _is_null_or_white_space(v2):
            return table
        if len(v2) > 80:
            wrapped = self.word_wrap(v2, 80)
            strchunks = wrapped.split("\n")
            # IEnumerable<String> strchunks = ChunksUpto(v2, 80);

            first = True
            for chunk in strchunks:
                if first:
                    table.add_row(v1, chunk.strip())
                    first = False
                else:
                    table.add_row("", chunk.strip())
        else:
            table.add_row(v1, v2)

        return table

    # PORT NOTE: `static char[] splitChars = new char[] { ' ', '-', '\t' };`
    split_chars = [" ", "-", "\t"]

    @staticmethod
    def word_wrap(str_: str, width: int) -> str:
        words = NiceGpoPrinter.explode(str_, NiceGpoPrinter.split_chars)

        cur_line_length = 0
        str_builder: List[str] = []
        for i in range(0, len(words)):
            word = words[i]
            # If adding the new word to the current line would be too long,
            # then put it on a new line (and split it up if it's too long).
            if cur_line_length + len(word) > width:
                # Only move down to a new line if we have text on the current line.
                # Avoids situation where wrapped whitespace causes emptylines in text.
                if cur_line_length > 0:
                    str_builder.append(NEWLINE)
                    cur_line_length = 0

                # If the current word is too long to fit on a line even on it's own then
                # split the word up.
                while len(word) > width:
                    str_builder.append(word[0 : width - 1] + "-")
                    word = word[width - 1 :]

                    str_builder.append(NEWLINE)

                # Remove leading whitespace from the word so the new line starts flush to the left.
                word = word.lstrip()
            str_builder.append(word)
            cur_line_length += len(word)

        return "".join(str_builder)

    @staticmethod
    def explode(str_: str, split_chars: List[str]) -> List[str]:
        parts: List[str] = []
        start_index = 0
        while True:
            # PORT NOTE: `string.IndexOfAny(char[], int)`.
            index = -1
            for split_char in split_chars:
                found = str_.find(split_char, start_index)
                if found != -1 and (index == -1 or found < index):
                    index = found

            if index == -1:
                parts.append(str_[start_index:])
                return parts

            word = str_[start_index:index]
            next_char = str_[index : index + 1][0]
            # Dashes and the likes should stick to the word occuring before it. Whitespace doesn't have to.
            if next_char.isspace():
                parts.append(word)
                parts.append(next_char)
            else:
                parts.append(word + next_char)

            start_index = index + 1

    def print_nice_aces(self, aces: List[SimpleAce]) -> str:
        sb: List[str] = []

        for ace in aces:
            sb.append("COMING SOON - ACLS!" + NEWLINE)
        return "".join(sb)

    def indent_para(self, in_string: str, indentfactor: int, tail_on: bool = True) -> str:
        istring = " " * self._indent
        fullindent = istring * indentfactor
        tailend = "_" * (self._indent - 1)
        tail = "\\" + tailend
        sb: List[str] = []
        taildent = istring * (indentfactor - 1)
        if tail_on:
            sb.append(taildent + tail + "\r\n" + fullindent)
        sb.append(in_string.replace("\r\n", "\r\n" + fullindent))
        return "".join(sb).rstrip() + "\r\n"
