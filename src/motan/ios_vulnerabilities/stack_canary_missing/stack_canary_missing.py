#!/usr/bin/env python3

import logging
import os
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import IOSAnalysis


class StackCanaryMissing(categories.ICodeVulnerability):
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
            stk_check = "___stack_chk_fail"
            stk_guard = "___stack_chk_guard"
            ipt_list = set()
            for ipt in analysis_info.macho_object.imported_functions:
                ipt_list.add(str(ipt))
            vulnerability_found = not (stk_check in ipt_list and stk_guard in ipt_list)
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
