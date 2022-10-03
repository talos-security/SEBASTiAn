#!/usr/bin/env python3

import logging
import os
from collections.abc import Iterable
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import IOSAnalysis


class AllowHttpPlist(categories.IPlistVulnerability):
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
                if "NSExceptionDomains" in ns_app_trans_dic:
                    for key in ns_app_trans_dic["NSExceptionDomains"]:
                        if (
                            isinstance(
                                ns_app_trans_dic["NSExceptionDomains"][key], Iterable
                            )
                            and "NSExceptionAllowsInsecureHTTPLoads"
                            in ns_app_trans_dic["NSExceptionDomains"][key]
                            and ns_app_trans_dic["NSExceptionDomains"][key][
                                "NSExceptionAllowsInsecureHTTPLoads"
                            ]
                            is True
                        ):
                            vulnerability_found = True
                            details.code.append(
                                vuln.VulnerableCode(
                                    "NSExceptionAllowsInsecureHTTPLoads is true "
                                    f"for domain '{key}'",
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
