#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.taint_analysis import TaintAnalysis


class CustomTaintAnalysis(TaintAnalysis):
    def vulnerable_path_found_callback(
        self,
        full_path: List[MethodAnalysis],
        caller: MethodAnalysis = None,
        target: MethodAnalysis = None,
        last_invocation_params: list = None,
    ):
        if (
            caller
            and target
            and last_invocation_params
            and len(last_invocation_params) > 3
        ):
            # 0 means that setEntry is called by passing a null value as the
            # protection parameter.
            if last_invocation_params[3] == 0:
                self.vulnerabilities[
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                ] = (
                    "KeyStore.setEntry invoked with null ProtectionParameter",
                    " --> ".join(
                        f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                    ),
                )


class CryptoKeystoreEntryWithoutPassword(categories.ICodeVulnerability):
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

            dx = analysis_info.get_dex_analysis()

            # The target method is setEntry in the KeyStore.
            target_method: MethodAnalysis = dx.get_method_analysis_by_name(
                "Ljava/security/KeyStore;",
                "setEntry",
                "(Ljava/lang/String; Ljava/security/KeyStore$Entry; "
                "Ljava/security/KeyStore$ProtectionParameter;)V",
            )

            taint_analysis = CustomTaintAnalysis(target_method, analysis_info)

            code_vulnerabilities = taint_analysis.find_code_vulnerabilities()

            if code_vulnerabilities:
                vulnerability_found = True
                details.code.extend(code_vulnerabilities)

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
