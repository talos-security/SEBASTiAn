#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.taint_analysis import TaintAnalysis, RegisterAnalyzer
from motan.util import is_class_implementing_interfaces


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
            and len(last_invocation_params) > 1
        ):
            try:
                hostname_verifier_class = last_invocation_params[-1].get_class_name()
            except Exception:
                hostname_verifier_class = None

            # Look for the implementation(s) of the HostnameVerifier interface
            # (https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
            # and check if the return value is hardcoded to true (1).
            interface_implementations = []
            classes = self._analysis_info.get_dex_analysis().get_internal_classes()
            for clazz in classes:
                if is_class_implementing_interfaces(
                    clazz.get_vm_class(), ["Ljavax/net/ssl/HostnameVerifier;"]
                ):
                    for method in clazz.get_vm_class().get_methods():
                        if (method.get_name() == "verify") and (
                            method.get_descriptor()
                            == "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
                        ):
                            register_analyzer = RegisterAnalyzer(
                                self._analysis_info.get_apk_analysis(),
                                self._analysis_info.get_dex_analysis(),
                            )
                            register_analyzer.load_instructions(
                                method.get_instructions()
                            )
                            result = register_analyzer.get_return_value()

                            # 1 means all hostnames are verified (the vulnerability is
                            # present).
                            if result == 1:
                                interface_implementations.append(
                                    method.get_class_name()
                                )

            # Check if hostname_verifier_class is in the list of classes that implement
            # HostnameVerifier interface with a hardcoded return value.
            if hostname_verifier_class in interface_implementations:
                # The key is the full method signature where the vulnerable code was
                # found, while the value is a tuple with the signature of the vulnerable
                # target method and the full path leading to the vulnerability.
                self.vulnerabilities[
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                ] = (
                    f"{hostname_verifier_class}->"
                    "verify(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z",
                    " --> ".join(
                        f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                    ),
                )


class InsecureHostnameVerifier(categories.ICodeVulnerability):
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

            # The target methods are the ones that set the HostnameVerifier.
            target_methods: List[MethodAnalysis] = [
                dx.get_method_analysis_by_name(
                    "Ljavax/net/ssl/HttpsURLConnection;",
                    "setHostnameVerifier",
                    "(Ljavax/net/ssl/HostnameVerifier;)V",
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/net/ssl/HttpsURLConnection;",
                    "setDefaultHostnameVerifier",
                    "(Ljavax/net/ssl/HostnameVerifier;)V",
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
