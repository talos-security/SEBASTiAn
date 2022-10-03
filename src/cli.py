#!/usr/bin/env python3

import argparse
import json
import logging
import os
from typing import List

from motan.main import perform_analysis_with_timeout

logger = logging.getLogger(__name__)


def get_cmd_args(args: List[str] = None):
    """
    Parse and return the command line parameters needed for the script execution.

    :param args: List of arguments to be parsed (by default sys.argv is used).
    :return: The command line needed parameters.
    """

    languages = ["en", "it"]

    parser = argparse.ArgumentParser(
        prog="python3 -m motan.cli",
        description="Find the security vulnerabilities of a mobile application "
                    "without needing its source code.",
    )
    parser.add_argument(
        "app_file",
        type=str,
        metavar="FILE",
        help="The path to the mobile application to analyze",
    )
    parser.add_argument(
        "-l",
        "--language",
        choices=languages,
        help="The language used for the vulnerabilities. "
             f"Allowed values are: {', '.join(languages)}",
        default="en",
    )
    parser.add_argument(
        "-i",
        "--ignore-libs",
        action="store_true",
        help="Ignore known third party libraries during the vulnerability analysis "
             "(only for Android)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Make the entire analysis fail on the first failed vulnerability check",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        metavar="TIMEOUT",
        default=1200,
        help="Make the analysis fail if it takes longer than timeout (in seconds) "
             "to complete. By default a timeout of 1200 seconds (20 minutes) is used",
    )
    parser.add_argument(
        "--keep-files",
        action="store_true",
        help="Keep intermediate files generated during the analysis (only for iOS)",
    )
    parser.add_argument(
        "--generate-report",
        action="store_true",
        help="Generate the report of the analysis in JSON format",
    )
    return parser.parse_args(args)


def main():
    arguments = get_cmd_args()

    if arguments.app_file:
        arguments.app_file = arguments.app_file.strip(" '\"")

    if arguments.language:
        arguments.language = arguments.language.strip(" '\"")

    if arguments.generate_report:
        os.makedirs('results', exist_ok=True)

    vuln_json_dict = perform_analysis_with_timeout(
        arguments.app_file,
        arguments.language,
        arguments.ignore_libs,
        arguments.fail_fast,
        arguments.keep_files,
        arguments.timeout,
        arguments.generate_report,
    )

    if arguments.generate_report:
        apk_name = os.path.basename(os.path.splitext(arguments.app_file)[0])
        with open(f"results{os.sep}{apk_name}.json", "w") as f:
            json.dump(vuln_json_dict, f, indent=2, ensure_ascii=False)
    """
    logger.info(
        "Analysis results:\n"
        f"{json.dumps(vuln_json_dict, indent=2, ensure_ascii=False)}"
    )
    """

    print(f"{json.dumps(vuln_json_dict, indent=2, ensure_ascii=False)}")


if __name__ == "__main__":
    main()
