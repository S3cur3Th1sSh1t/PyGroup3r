"""Port of Group3r/Options/GrouperOptions.cs."""

from typing import Optional

from .assessment_options import AssessmentOptions


class GrouperOptions:
    """Port of Group3r.Options.GrouperOptions.

    Field defaults are the C# property initialisers, unchanged.
    """

    def __init__(self):
        # Manual Targeting Options
        self.sysvol_path: Optional[str] = None
        self.offline_mode: bool = False
        self.target_domain: Optional[str] = None
        self.target_dc: Optional[str] = None
        self.password: Optional[str] = None
        self.username: Optional[str] = None
        self.current_pol_only: bool = False
        self.enabled_pol_only: bool = False
        self.quiet_mode: bool = False
        # PORT NOTE: the C# default is `WindowsIdentity.GetCurrent().Name`, i.e.
        # the identity of the Windows session Group3r is running in. There is no
        # such session here, so OptionsParser fills this in from the credentials
        # it was given (`DOMAIN\\username`) unless --testuser says otherwise.
        self.target_user_name: Optional[str] = None

        # Concurrency Options
        self.max_threads: int = 30
        self.max_sysvol_threads: int = 15
        self.max_gpoa_threads: int = 15
        self.max_sysvol_queue: int = 0
        self.max_gpoa_queue: int = 0

        # Logging Options
        self.log_to_file: bool = False
        self.log_file_path: Optional[str] = None
        self.separator: str = " "
        self.log_to_console: bool = True
        self.log_level_string: str = "info"
        self.printer_type: Optional[str] = None
        self.findings_only: bool = False

        # PORT ADDITIONS: authentication material the C# takes from the Windows
        # session, plus the path for the new filterable HTML report. Nothing else
        # about the CLI surface changes. See options_parser.py.
        self.hashes: Optional[str] = None
        self.kerberos: bool = False
        self.aes_key: Optional[str] = None
        self.dc_ip: Optional[str] = None
        self.html_path: Optional[str] = None
        # PORT ADDITIONS: GPO scope ("blast radius") resolution and BloodHound export.
        self.resolve_scope: bool = False
        self.scope_users: bool = False
        self.bloodhound_path: Optional[str] = None
        # PORT ADDITION: show full REG_BINARY hex instead of compact preview.
        self.show_blob: bool = False

        # public AutoMapper.ConfigurationStore AutoMapperConfig { get; set; }
        # public AutoMapper.MappingEngine MappingEngine { get; set; }

        # Imported here rather than at module scope: view.gpo_printer_factory
        # pulls in the printers, which import the setting types.
        from ..view.gpo_printer_factory import get_printer

        self.printer = get_printer(self.printer_type, self)

        self.assessment_options = AssessmentOptions()
