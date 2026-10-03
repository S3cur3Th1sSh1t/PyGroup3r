"""Port of Group3r/Options/OptionsParser.cs.

Static class to house cmd argument parsing into options.
TODO: Max thread settings are currently hardcoded and cmd args are no respected.

PORT NOTE: the C# uses the `CommandLineParser` NuGet package; this port uses
`argparse`. Every original flag keeps its exact short name, long name and help
text, and the options are still applied in *declaration* order (not
command-line order) so the Degub messages come out in the same sequence.

The only additions are the ones the impacket port cannot do without - see the
"PORT ADDITION" block in build_parser() - because the C# gets its credentials and
its DC from the Windows session it runs in, and because this port also emits an
HTML report.
"""

import argparse
from typing import List, Optional

from ..classifiers.constants import Triage


class CommandLineArgumentException(Exception):
    """PORT NOTE: stands in for CommandLineParser.Exceptions.CommandLineArgumentException."""

    def __init__(self, message: str, value: Optional[str] = None):
        super().__init__(message)
        self.value = value


def _is_null_or_empty(value: Optional[str]) -> bool:
    """PORT NOTE: `String.IsNullOrEmpty`."""
    return value is None or value == ""


# The long names in the order the C# adds them to the parser. `parser.Arguments`
# is iterated in this order, so this is the order the switch below sees them in.
_DECLARATION_ORDER: List[str] = [
    "dc",
    "domain",
    "help",
    "offline",
    "outfile",
    "stdout",
    "sysvol",
    "threads",
    "verobsity",
    "currentonly",
    "findingsonly",
    "mintriage",
    "testuser",
    "enabled",
    # PORT ADDITIONS, declared last so they cannot reorder anything above.
    "username",
    "password",
    "hashes",
    "kerberos",
    "aes-key",
    "dc-ip",
    "html",
    "scope",
    "scope-users",
    "bloodhound",
]

# Long name -> (argparse dest, is switch).
_ARG_INFO = {
    "dc": ("dc", False),
    "domain": ("domain", False),
    "help": ("help", True),
    "offline": ("offline", True),
    "outfile": ("outfile", False),
    "stdout": ("stdout", True),
    "sysvol": ("sysvol", False),
    "threads": ("threads", False),
    "verobsity": ("verobsity", False),
    "currentonly": ("currentonly", True),
    "findingsonly": ("findingsonly", True),
    "mintriage": ("mintriage", False),
    "testuser": ("testuser", False),
    "enabled": ("enabled", True),
    "username": ("username", False),
    "password": ("password", False),
    "hashes": ("hashes", False),
    "kerberos": ("kerberos", True),
    "aes-key": ("aes_key", False),
    "dc-ip": ("dc_ip", False),
    "html": ("html", False),
    "scope": ("scope", True),
    "scope-users": ("scope_users", True),
    "bloodhound": ("bloodhound", False),
}


def build_parser() -> argparse.ArgumentParser:
    """Summary: Defines cmd line args and adds them to a parser.
    Arguments: None
    Returns: argparse.ArgumentParser object
    """
    parser = argparse.ArgumentParser(prog="group3r", add_help=False)

    # letters i haven't used abegijklmnw
    # parser.Arguments.Add(new ValueArgument<string>('z', "config", "Path to a .toml config file. Run with 'generate' to puke a sample config file into the working directory."));
    parser.add_argument("-c", "--dc", help="Target Domain controller")
    parser.add_argument("-d", "--domain", help="Domain to query.")
    parser.add_argument("-h", "--help", action="store_true", help="Displays this help.")
    parser.add_argument(
        "-o",
        "--offline",
        action="store_true",
        help="Disables checks that require LDAP comms with a DC or SMB comms with file shares found in policy settings. Requires that you define a value for -y.",
    )
    parser.add_argument(
        "-f", "--outfile", help="Path for output file. You probably want this if you're not using -s."
    )
    parser.add_argument(
        "-s",
        "--stdout",
        action="store_true",
        help="Enables outputting results to stdout as soon as they're found. You probably want this if you're not using -f.",
    )
    parser.add_argument("-y", "--sysvol", help="Set the path to a domain SYSVOL directory.")
    parser.add_argument("-t", "--threads", type=int, help="Max number of threads. Defaults to 10.")
    parser.add_argument(
        "-v",
        "--verobsity",
        help="Sets verobsity level. Do you want degubs? Options are 'info' (default), 'debug', 'degub', and 'trace'.",
    )
    parser.add_argument(
        "-r",
        "--currentonly",
        action="store_true",
        help="Only checks current policies, ignoring stuff in those Policies_NTFRS_* directories that result from replication failures.",
    )
    parser.add_argument(
        "-w", "--findingsonly", action="store_true", help="Only displays settings that had an associated finding."
    )
    parser.add_argument(
        "-a",
        "--mintriage",
        type=int,
        help="Minimum severity of findings to show where 1 is lowest severity and 4 is highest.",
    )
    parser.add_argument(
        "--testuser",
        help="Permission checks will focus on what access is available to this user. Format as domain\\user",
    )
    parser.add_argument(
        "-e", "--enabled", action="store_true", help="Only displays policy types and settings that are enabled."
    )

    # PORT ADDITIONS. The C# picks the current user's credentials and DC up from
    # the Windows session; on Linux/impacket they have to be given explicitly.
    # NOTE: -u is the impacket-style short form for --username. --testuser keeps
    # long-only form to avoid the clash. -d/--domain is the original's flag and
    # doubles as the auth domain.
    parser.add_argument("-u", "--username", help="PORT ADDITION: username to authenticate with.")
    parser.add_argument("-p", "--password", help="PORT ADDITION: password to authenticate with.")
    parser.add_argument(
        "-H", "--hashes", metavar="LMHASH:NTHASH", help="PORT ADDITION: NTLM hashes to authenticate with."
    )
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="PORT ADDITION: use Kerberos authentication, from the ccache in KRB5CCNAME if credentials are not given.",
    )
    parser.add_argument("--aes-key", help="PORT ADDITION: AES key to use for Kerberos authentication.")
    parser.add_argument("--dc-ip", help="PORT ADDITION: IP address of the domain controller.")
    parser.add_argument("--html", help="PORT ADDITION: path for the filterable HTML report.")
    parser.add_argument(
        "--scope",
        action="store_true",
        help="PORT ADDITION: resolve which computers each GPO actually applies to "
        "(gPLink status, block inheritance, enforced links, security filtering). "
        "Needs LDAP, so it is ignored in offline mode.",
    )
    parser.add_argument(
        "--scope-users",
        action="store_true",
        help="PORT ADDITION: also enumerate affected users when resolving scope. "
        "Implies --scope and can be slow on a large domain.",
    )
    parser.add_argument(
        "--bloodhound",
        help="PORT ADDITION: path prefix for BloodHound edge export; writes "
        "<prefix>.json and <prefix>.cypher. Implies --scope.",
    )
    return parser


def parse(args: List[str], mq):
    """Summary: Parses the actual cmd line args provided into an Options object.
             Also submits some messages to the Mq regarding config.
    Arguments: Array of command line args
    Returns: GrouperOptions object
    """
    from .grouper_options import GrouperOptions

    options = GrouperOptions()
    parser = build_parser()

    # extra check to handle builtin behaviour from cmd line arg parser
    if "--help" in args or "/?" in args or "help" in args or "-h" in args or len(args) == 0:
        parser.print_help()
        # TODO: avoid an exit like this, prefer to return to caller.
        return None

    #   TomlSettings settings = TomlSettings.Create(cfg => cfg
    #       .ConfigureType<LogLevel>(tc => tc
    #           .WithConversionFor<TomlString>(conv => conv
    #               .FromToml(s => (LogLevel)Enum.Parse(typeof(LogLevel), s.Value, ignoreCase: true))
    #               .ToToml(e => e.ToString()))));

    parsed = parser.parse_args(args)

    # Iterate over each arg where parsed is True.
    for long_name in _DECLARATION_ORDER:
        dest, is_switch = _ARG_INFO[long_name]
        raw = getattr(parsed, dest)
        if is_switch:
            if not raw:
                continue
        elif raw is None:
            continue

        # Grab the value here to save typecasting every instance of ValueArgument.
        value = ""
        if is_switch:
            value = ""
        else:
            value = str(raw)

        # case "config":
        #     if (value.Equals("generate"))
        #     {
        #         // Generate a default config and return.
        #         Toml.WriteFile(options, ".\\default.toml", settings);
        #         mq.Info("Wrote default config values to .\\default.toml");
        #         mq.Terminate();
        #     }
        #     else
        #     {
        #         // Read the specified config file and return.
        #         options = Toml.ReadFile<GrouperOptions>(value, settings);
        #         mq.Info("Read config file from " + value);
        #     }
        #     return options;
        if long_name == "offline":
            options.offline_mode = True
        elif long_name == "outfile":
            if not _is_null_or_empty(value):
                options.log_to_file = True
                options.log_file_path = value
                mq.degub("Logging to file at " + options.log_file_path)
        elif long_name == "verobsity":
            options.log_level_string = value
            mq.degub("Requested verbosity level: " + options.log_level_string)
        elif long_name == "stdout":
            # If enabled, display findings to the console.
            options.log_to_console = True
            mq.degub("Enabled logging to stdout.")
        elif long_name == "mintriage":
            t = None
            try:
                t = int(value)
            except ValueError:
                t = None
            if t is not None:
                # PORT NOTE: the C# cast `(Triage)t` does not validate, so -a 4
                # (which the help text calls the highest severity, even though
                # Triage only runs 0-3) leaves an out-of-range value in there.
                # Triage is an IntEnum, so keeping the bare int preserves both the
                # stored value and every comparison made against it.
                try:
                    options.assessment_options.min_triage = Triage(t)
                except ValueError:
                    options.assessment_options.min_triage = t
            else:
                mq.error("Invalid mintriage argument passed. Arg only accepts integers between 1 and 4.")
        elif long_name == "domain":
            # Args that tell us about targeting.
            if not _is_null_or_empty(value):
                options.target_domain = value
                mq.degub("Target domain is " + value)
        elif long_name == "enabled":
            options.enabled_pol_only = True
            mq.degub("Limiting output to enabled policy only.")
        elif long_name == "testuser":
            options.target_user_name = value

        #
        # case "username":
        #     if (!String.IsNullOrEmpty(value))
        #     {
        #         options.Username = value;
        #         mq.Degub("Username for LDAP is " + value);
        #     }
        #     break;
        #
        # case "password":
        #     if (!String.IsNullOrEmpty(value))
        #     {
        #         options.Password = value;
        #         mq.Degub("Password for LDAP is " + value);
        #     }
        #     break;
        # case "quiet":
        #     options.QuietMode = true;
        #     break;
        #
        elif long_name == "dc":
            options.target_dc = value
            mq.degub("Target DC is " + value)
        elif long_name == "sysvol":
            options.sysvol_path = value
            mq.degub("Disabled finding SYSVOL automatically.")
            mq.degub("Target SYSVOL path is " + value)
        elif long_name == "currentonly":
            options.current_pol_only = True
        elif long_name == "findingsonly":
            options.findings_only = True
        elif long_name == "threads":
            options.max_threads = int(value)
        elif long_name == "printer":
            options.printer_type = value

        # PORT ADDITIONS. The username case revives the commented-out C# one
        # above; the password is *not* echoed to the queue.
        elif long_name == "username":
            if not _is_null_or_empty(value):
                options.username = value
                mq.degub("Username for LDAP is " + value)
        elif long_name == "password":
            if not _is_null_or_empty(value):
                options.password = value
        elif long_name == "hashes":
            options.hashes = value
        elif long_name == "kerberos":
            options.kerberos = True
            mq.degub("Using Kerberos authentication.")
        elif long_name == "aes-key":
            options.aes_key = value
        elif long_name == "dc-ip":
            options.dc_ip = value
        elif long_name == "html":
            options.html_path = value
            mq.degub("Writing HTML report to " + value)
        elif long_name == "scope":
            options.resolve_scope = True
            mq.degub("Resolving GPO scope.")
        elif long_name == "scope-users":
            options.resolve_scope = True
            options.scope_users = True
            mq.degub("Resolving GPO scope, including affected users.")
        elif long_name == "bloodhound":
            options.bloodhound_path = value
            # Edges are meaningless without knowing which computers a GPO reaches.
            options.resolve_scope = True
            mq.degub("Writing BloodHound edge export to " + value)
        else:
            raise CommandLineArgumentException(
                "Something went real squirrelly in the command line args.", value
            )

    # PORT NOTE: GrouperOptions.TargetUserName defaults to
    # WindowsIdentity.GetCurrent().Name in the C#. With no Windows session to ask,
    # the credentials we were handed stand in for it: DOMAIN\username, or just the
    # username when no domain was given. --testuser still wins, exactly as it
    # does in the original.
    if _is_null_or_empty(options.target_user_name) and not _is_null_or_empty(options.username):
        if not _is_null_or_empty(options.target_domain):
            options.target_user_name = options.target_domain + "\\" + options.username
        else:
            options.target_user_name = options.username

    # Quality bants with dumbo users
    if not options.log_to_console and not options.log_to_file:
        raise ValueError(
            "You didn't enable output to file or to the console so you won't see any results or debugs or anything. Your l0ss."
        )
    if _is_null_or_empty(options.sysvol_path) and options.offline_mode:
        raise ValueError(
            "You have specified offline mode but not specified a path to SysVol. I can just make shit up I guess?"
        )

    mq.info("Parsed args successfully.")
    return options


class OptionsParser:
    """Static class in the C#; kept as a namespace so call sites read the same."""

    build_parser = staticmethod(build_parser)
    parse = staticmethod(parse)
