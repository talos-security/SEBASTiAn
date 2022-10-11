#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.taint_analysis import TaintAnalysis


class CustomTaintAnalysis(TaintAnalysis):
    def find_params(self, full_path, method, actual_depth, depth):
        if actual_depth == depth:
            return False

        method_dicts = []
        for i in method.get_instructions():
            if str(i).startswith("invoke") and str(
                full_path[actual_depth + 1].get_method().get_name()
            ) in str(i):
                dict_param = {}
                for param in str(i).split(" ")[1:-1]:
                    dict_param[param[:-1]] = []
                method_dicts.append(dict_param)

        for i in method.get_instructions():
            if str(i).startswith("const-string"):
                for dict_method in method_dicts:
                    for key in dict_method:
                        if key in str(i):
                            dict_method[key].append(str(i).split(" ")[-1].strip())
                            break

        for dict_method in method_dicts:
            for key in dict_method:
                for value in dict_method[key]:
                    if value == "AES":
                        return True

        if actual_depth > 0 and self.find_params(
            full_path,
            full_path[actual_depth - 1].get_method(),
            actual_depth=actual_depth + 1,
            depth=depth,
        ):
            return True

        return False

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
            and len(last_invocation_params) > 1
        ):
            if isinstance(last_invocation_params[1], str):
                # The key is the full method signature where the vulnerable code was
                # found, while the value is a tuple with the signature of the vulnerable
                # target method and the full path leading to the vulnerability.
                self.vulnerabilities[
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                ] = (
                    f'constant IV "{last_invocation_params[1]}" parameter passed '
                    "to IvParameterSpec",
                    " --> ".join(
                        f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                    ),
                )


class CryptoConstantIv(categories.ICodeVulnerability):
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

            # The target methods are IvParameterSpec constructors.
            target_methods: List[MethodAnalysis] = [
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/IvParameterSpec;", "<init>", "([B)V"
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/IvParameterSpec;", "<init>", "([B I I)V"
                ),
            ]

            taint_analysis = CustomTaintAnalysis(target_methods, analysis_info)

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
