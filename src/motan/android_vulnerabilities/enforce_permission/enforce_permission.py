#!/usr/bin/env python3

import logging
import os
from typing import Optional, List, Union, Iterable

from androguard.core.analysis.analysis import MethodAnalysis

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.taint_analysis import TaintAnalysis


class CustomTaintAnalysis(TaintAnalysis):

    def __init__(
            self,
            target_method: Union[MethodAnalysis, Iterable[MethodAnalysis]],
            analysis_info: AndroidAnalysis,
            path_max_length: int = 5,
    ):
        super().__init__(target_method, analysis_info, path_max_length)
        self.my_pid = False
        self.my_uid = False

    def taint_param(self, full_path: List[MethodAnalysis]):
        prev_method = full_path[-1]
        param_tainted_for_method = [1]
        for method_analysis in full_path[-2::-1]:
            is_param = False
            to_taint_var = -1
            for instruction in method_analysis.get_method().get_instructions():
                if (
                        instruction.get_op_value() in [0x6E, 0x71] and
                        instruction.get_operands()[-1][-1] in str(prev_method)
                ):
                    params = method_analysis.get_method().get_information().get("params")
                    if params:
                        for i in range(len(params)):
                            if params[i][0] == instruction.get_operands()[param_tainted_for_method[-1]][1]:
                                param_tainted_for_method.append(i)
                                is_param = True
                                break
                    if not params or not is_param:
                        to_taint_var = instruction.get_operands()[param_tainted_for_method[-1]][1]
                    break

            if not is_param and to_taint_var >= 0:
                for instruction in method_analysis.get_method().get_instructions():
                    if instruction.get_op_value() == 0x1A and instruction.get_operands()[0][1] == to_taint_var:
                        permission = instruction.get_operands()[1][-1]
                        if "." in permission and " " not in permission and not permission.startswith(
                                "android.permission"):
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
                full_path[-1].get_method().get_name() == "getCallingPid" and
                full_path[-1].get_method().get_descriptor() == "()I" and
                full_path[-1].get_method().get_class_name() == "Landroid/os/Binder;"
        ):
            self.my_pid = True

        elif (
                full_path[-1].get_method().get_name() == "getCallingUid" and
                full_path[-1].get_method().get_descriptor() == "()I" and
                full_path[-1].get_method().get_class_name() == "Landroid/os/Binder;"
        ):
            self.my_uid = True

        elif self.my_pid and self.my_uid:
            if (len(last_invocation_params) > 0 and last_invocation_params[1] is not None and not
            last_invocation_params[1].startswith("android.permission")) or self.taint_param(full_path):
                self.vulnerabilities[
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                ] = (
                    f"{target.class_name}->{target.name}{target.descriptor}",
                    " --> ".join(
                        f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                    ),
                )


class EnforcePermission(categories.ICodeVulnerability):
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

            classes = ["Landroid/app/Service;", "Landroid/content/Context;", "Landroid/app/Activity;"]

            target_method: List[MethodAnalysis] = [
                dx.get_method_analysis_by_name(
                    "Landroid/os/Binder;",
                    "getCallingPid",
                    "()I"
                ),
                dx.get_method_analysis_by_name(
                    "Landroid/os/Binder;",
                    "getCallingUid",
                    "()I"
                ),
            ]

            target_method.extend(
                [dx.get_method_analysis_by_name(
                    caller,
                    "enforcePermission",
                    "(Ljava/lang/String; I I Ljava/lang/String;)V"
                ) for caller in classes]
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
