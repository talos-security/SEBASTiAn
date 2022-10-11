#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.taint_analysis import TaintAnalysis


class CustomTaintAnalysis(TaintAnalysis):
    def taint_param(self, full_path: List[MethodAnalysis]):
        prev_method = full_path[-1]
        param_tainted_for_method = [1]
        for method_analysis in full_path[-2::-1]:
            is_param = False
            to_taint_var = -1
            for instruction in method_analysis.get_method().get_instructions():
                if instruction.get_op_value() in [
                    0x6E,
                    0x71,
                ] and instruction.get_operands()[-1][-1] in str(prev_method):
                    params = (
                        method_analysis.get_method().get_information().get("params")
                    )
                    if params:
                        for i in range(len(params)):
                            if (
                                params[i][0]
                                == instruction.get_operands()[
                                    param_tainted_for_method[-1]
                                ][1]
                            ):
                                param_tainted_for_method.append(i)
                                is_param = True
                                break
                    if not params or not is_param:
                        to_taint_var = instruction.get_operands()[
                            param_tainted_for_method[-1]
                        ][1]
                    break

            if not is_param and to_taint_var >= 0:
                for instruction in method_analysis.get_method().get_instructions():
                    if (
                        0x12 <= instruction.get_op_value() <= 0x1A
                        and instruction.get_operands()[0][1] == to_taint_var
                    ):
                        if instruction.get_operands()[1][1] == 0x1:
                            return True
                return False

            prev_method = method_analysis

    def vulnerable_path_found_callback(
        self,
        full_path: List[MethodAnalysis],
        caller: MethodAnalysis = None,
        target: MethodAnalysis = None,
        last_invocation_params: list = None,
    ):
        if (
            len(last_invocation_params) > 0 and last_invocation_params[1] == 1
        ) or self.taint_param(full_path):
            # The key is the full method signature where the vulnerable code was
            # found, while the value is a tuple with the signature of the vulnerable
            # target method and the full path leading to the vulnerability.
            self.vulnerabilities[
                f"{caller.class_name}->{caller.name}{caller.descriptor}"
            ] = (
                f"{target.class_name}->{target.name}{target.descriptor}",
                " --> ".join(
                    f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                ),
            )


class WebViewAllowFileAccess(categories.ICodeVulnerability):
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

            # The target method is the WebView API that enables file access
            # https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)
            target_method: MethodAnalysis = dx.get_method_analysis_by_name(
                "Landroid/webkit/WebSettings;", "setAllowFileAccess", "(Z)V"
            )

            # The list of methods that contain the vulnerability. The key is the
            # full method signature where the vulnerable code was found, while the
            # value is a tuple with the signature of the vulnerable API/other info
            # about the vulnerability and the full path leading to the
            # vulnerability.
            vulnerable_methods = {}

            if not target_method:
                # The target method was not found. Before Android R (API 30), file
                # access within WebView is enabled by default, so we have to check
                # if WebView is used.
                target_sdk = analysis_info.get_apk_analysis().get_target_sdk_version()
                if (
                    target_sdk
                    and int(analysis_info.get_apk_analysis().get_target_sdk_version())
                    < 30
                ):
                    class_analysis = dx.get_class_analysis(
                        "Landroid/webkit/WebSettings;"
                    )
                    # The target class was not found, there is no reason to continue
                    # checking this vulnerability.
                    if not class_analysis:
                        return None
                    for caller in class_analysis.get_xref_from():
                        for m in caller.get_methods():
                            m = m.get_method()

                            # Ignore excluded methods (if any).
                            if analysis_info.ignore_libs:
                                if any(
                                    m.get_class_name().startswith(prefix)
                                    for prefix in analysis_info.ignored_classes_prefixes
                                ):
                                    continue

                            if isinstance(m, EncodedMethod):
                                for i in m.get_instructions():
                                    if i.get_output().endswith(
                                        "Landroid/webkit/WebView;->"
                                        "getSettings()Landroid/webkit/WebSettings;"
                                    ):
                                        # WebSettings was found.

                                        taint_analysis = CustomTaintAnalysis(
                                            dx.get_method(m), analysis_info
                                        )
                                        path_to_caller = (
                                            taint_analysis.get_paths_to_target_method()[
                                                0
                                            ]
                                        )

                                        vulnerable_methods[
                                            f"{m.get_class_name()}->"
                                            f"{m.get_name()}{m.get_descriptor()}"
                                        ] = (
                                            "Landroid/webkit/WebSettings;",
                                            " --> ".join(
                                                f"{p.class_name}->"
                                                f"{p.name}{p.descriptor}"
                                                for p in path_to_caller
                                            ),
                                        )

                    for key, value in vulnerable_methods.items():
                        vulnerability_found = True
                        details.code.append(
                            vuln.VulnerableCode(value[0], key, value[1])
                        )
            else:
                # Check all the places where the target method is used, and put the
                # caller method in the list with the vulnerabilities if all the
                # conditions are met.
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
