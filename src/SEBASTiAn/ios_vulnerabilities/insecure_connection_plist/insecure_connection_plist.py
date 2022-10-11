#!/usr/bin/env python3

import logging
import os
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import IOSAnalysis


class InsecureConnectionPlist(categories.IPlistVulnerability):
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
            if "NSAppTransportSecurity" in analysis_info.plist_readable:
                ns_app_trans_dic = analysis_info.plist_readable[
                    "NSAppTransportSecurity"
                ]
                if (
                    "NSAllowsArbitraryLoads" in ns_app_trans_dic
                    and ns_app_trans_dic["NSAllowsArbitraryLoads"]
                ):
                    vulnerability_found = True
                    details.code.append(
                        vuln.VulnerableCode(
                            "NSAllowsArbitraryLoads is true",
                            "Info.plist",
                            "Info.plist",
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
