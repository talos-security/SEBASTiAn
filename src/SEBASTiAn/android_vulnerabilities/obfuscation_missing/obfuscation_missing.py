#!/usr/bin/env python3

import logging
import os
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis


class ObfuscationMissing(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: AndroidAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            vulnerability_found = False

            # Load the vulnerability details.
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            (
                ascii_obfuscation_rate,
                short_name_obfuscation_rate,
            ) = analysis_info.get_obfuscation_rates()

            if ascii_obfuscation_rate < 30 and short_name_obfuscation_rate < 30:
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        f"ASCII Obfuscation: {ascii_obfuscation_rate:.2f}% "
                        f"Renaming Obfuscation: {short_name_obfuscation_rate:.2f}%",
                        "application",
                        "application",
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
