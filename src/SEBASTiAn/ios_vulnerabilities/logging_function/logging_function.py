#!/usr/bin/env python3

import logging
import os
import re
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import IOSAnalysis


class LoggingFunction(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: IOSAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            vulnerability_found = False

            # TODO: add a configuration file from where to read the API(s).
            debug = re.findall(
                "_NSLog|_debugPrint|_println|_print|_dump", analysis_info.macho_symbols
            )
            debug_api = sorted(set(debug))
            if len(debug_api) > 0:
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        ", ".join(debug_api),
                        f"{analysis_info.bin_name} binary ({analysis_info.bin_arch})",
                        f"{analysis_info.bin_name} binary ({analysis_info.bin_arch})",
                    )
                )

            if vulnerability_found:
                return details
            else:
                return None

        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)
