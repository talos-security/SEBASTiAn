#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.taint_analysis import TaintAnalysis


class CustomTaintAnalysisKeySpec(TaintAnalysis):
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
            try:
                iterations = int(last_invocation_params[3])
                if iterations < 1000:
                    # The key is the full method signature where the vulnerable code was
                    # found, while the value is a tuple with the signature of the
                    # vulnerable target method and the full path leading to the
                    # vulnerability.
                    self.vulnerabilities[
                        f"{caller.class_name}->{caller.name}{caller.descriptor}"
                    ] = (
                        f"small number of iterations ({iterations}) passed "
                        "to PBEKeySpec",
                        " --> ".join(
                            f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                        ),
                    )
            except Exception:
                pass


class CustomTaintAnalysisParameterSpec(TaintAnalysis):
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
            and len(last_invocation_params) > 2
        ):
            try:
                iterations = int(last_invocation_params[2])
                if iterations < 1000:
                    # The key is the full method signature where the vulnerable code was
                    # found, while the value is a tuple with the signature of the
                    # vulnerable target method and the full path leading to the
                    # vulnerability.
                    self.vulnerabilities[
                        f"{caller.class_name}->{caller.name}{caller.descriptor}"
                    ] = (
                        f"small number of iterations ({iterations}) passed "
                        "to PBEKeySpec",
                        " --> ".join(
                            f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                        ),
                    )
            except Exception:
                pass


class CryptoSmallIterationCount(categories.ICodeVulnerability):
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

            # The target methods are PBEKeySpec constructors.
            target_methods_keyspec: List[MethodAnalysis] = [
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEKeySpec;", "<init>", "([C [B I)V"
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEKeySpec;", "<init>", "([C [B I I)V"
                ),
            ]

            # The target methods are PBEParameterSpec constructors.
            target_methods_parameterspec: List[MethodAnalysis] = [
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEParameterSpec;", "<init>", "([B I)V"
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEParameterSpec;",
                    "<init>",
                    "([B I Ljava/security/spec/AlgorithmParameterSpec;)V",
                ),
            ]

            taint_analysis_keyspec = CustomTaintAnalysisKeySpec(
                target_methods_keyspec, analysis_info
            )
            taint_analysis_parameterspec = CustomTaintAnalysisParameterSpec(
                target_methods_parameterspec, analysis_info
            )

            code_vulnerabilities_keyspec = (
                taint_analysis_keyspec.find_code_vulnerabilities()
            )
            code_vulnerabilities_parameterspec = (
                taint_analysis_parameterspec.find_code_vulnerabilities()
            )

            if code_vulnerabilities_keyspec or code_vulnerabilities_parameterspec:
                vulnerability_found = True
                details.code.extend(code_vulnerabilities_keyspec)
                details.code.extend(code_vulnerabilities_parameterspec)

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
