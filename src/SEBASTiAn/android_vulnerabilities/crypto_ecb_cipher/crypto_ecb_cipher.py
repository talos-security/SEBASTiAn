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
    def find_params(
        self, full_path, method, tainted_params, full_path_index, actual_depth, depth
    ):
        if actual_depth == depth:
            return False

        method_dicts = []
        new_tainted_params = set()
        for i in method.get_instructions():
            if str(i).startswith("invoke") and str(
                full_path[full_path_index + 1].get_method().get_name()
            ) in str(i):
                dict_params = {}
                for param_position in list(tainted_params):
                    param_name = str(i).split(" ")[1:-1][param_position][:-1]
                    reg_int = int(param_name[1:])
                    is_param = False
                    if method.get_information().get("params") is not None:
                        for param_index in range(
                            len(method.get_information().get("params"))
                        ):
                            if (
                                reg_int
                                == method.get_information().get("params")[param_index][
                                    0
                                ]
                            ):
                                new_tainted_params.add(param_index)
                                is_param = True
                                break
                        if not is_param:
                            dict_params[param_name] = []
                method_dicts.append(dict_params)

        for i in method.get_instructions():
            if str(i).startswith("const-string"):
                for dict_method in method_dicts:
                    for key in dict_method:
                        if key in str(i):
                            dict_method[key].append(str(i).split(" ")[-1].strip('"'))
                            break

        for dict_method in method_dicts:
            for key in dict_method:
                for value in dict_method[key]:
                    if value == "AES":
                        return True

        if full_path_index > 0 and self.find_params(
            full_path,
            full_path[full_path_index - 1].get_method(),
            new_tainted_params,
            full_path_index - 1,
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
            and len(last_invocation_params) > 0
        ):
            if isinstance(last_invocation_params[0], str):
                # Algorithm, mode, padding.
                tokens = last_invocation_params[0].split("/")

                if tokens[0].startswith("AES"):
                    # Default mode is ECB.
                    if len(tokens) == 1 or (
                        len(tokens) > 1 and (not tokens[1] or tokens[1] == "ECB")
                    ):
                        # The key is the full method signature where the vulnerable code
                        # was found, while the value is a tuple with the signature of
                        # the vulnerable target method and the full path leading to the
                        # vulnerability.
                        self.vulnerabilities[
                            f"{caller.class_name}->{caller.name}{caller.descriptor}"
                        ] = (
                            f'insecure cipher "{last_invocation_params[0]}"',
                            " --> ".join(
                                f"{p.class_name}->{p.name}{p.descriptor}"
                                for p in full_path
                            ),
                        )
            else:
                tainted_params = {0}
                full_path_index = len(full_path) - 2
                if self.find_params(
                    full_path,
                    full_path[full_path_index].get_method(),
                    tainted_params,
                    full_path_index,
                    actual_depth=0,
                    depth=3,
                ):
                    self.vulnerabilities[
                        f"{caller.class_name}->{caller.name}{caller.descriptor}"
                    ] = (
                        f'insecure cipher "{last_invocation_params[0]}"',
                        " --> ".join(
                            f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                        ),
                    )


class CryptoEcbCipher(categories.ICodeVulnerability):
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

            # The target method is the encryption cipher.
            target_method: MethodAnalysis = dx.get_method_analysis_by_name(
                "Ljavax/crypto/Cipher;",
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
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
