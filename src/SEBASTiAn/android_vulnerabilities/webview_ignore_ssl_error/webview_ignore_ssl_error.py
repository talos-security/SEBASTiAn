#!/usr/bin/env python3

import logging
import os
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis


class WebViewIgnoreSslError(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def analyze_method_rec(self, dx, method, actual_depth, depth):
        if actual_depth == depth:
            return False

        for i in method.get_instructions():
            if i.get_output().endswith("Landroid/webkit/SslErrorHandler;->proceed()V"):
                return True

            if str(i).startswith("invoke"):
                method_sig = str(i)[str(i).rindex(" ") + 1 :]
                method_class = method_sig.split("->")[0]

                remaining_str = method_sig.split("->")[1]
                method_name = remaining_str[0 : remaining_str.index("(")]
                method_signature = remaining_str[remaining_str.index("(") :]
                target_method = dx.get_method_analysis_by_name(
                    method_class, method_name, method_signature
                )
                if self.analyze_method_rec(
                    dx,
                    target_method.get_method(),
                    actual_depth=actual_depth + 1,
                    depth=depth,
                ):
                    return True
        return False

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

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # a tuple with the signature of the vulnerable API/other info about the
            # vulnerability and the full path leading to the vulnerability.
            vulnerable_methods = {}

            # Look for subclasses of WebViewClient and check onReceivedSslError
            # (https://developer.android.com/reference/android/webkit/WebViewClient)
            classes = dx.get_internal_classes()
            for clazz in classes:
                if (
                    clazz.get_vm_class().get_superclassname()
                    == "Landroid/webkit/WebViewClient;"
                ):
                    # Ignore excluded classes (if any).
                    if analysis_info.ignore_libs:
                        if any(
                            clazz.name.startswith(prefix)
                            for prefix in analysis_info.ignored_classes_prefixes
                        ):
                            continue

                    for method in clazz.get_vm_class().get_methods():
                        if (
                            method.name == "onReceivedSslError"
                            and method.descriptor == "(Landroid/webkit/WebView; "
                            "Landroid/webkit/SslErrorHandler; "
                            "Landroid/net/http/SslError;)V"
                        ):
                            found_proceed = False
                            for i in method.get_instructions():
                                if i.get_output().endswith(
                                    "Landroid/webkit/SslErrorHandler;->proceed()V"
                                ):
                                    found_proceed = True
                                    vulnerable_methods[method.get_class_name()] = (
                                        f"{method.get_name()}{method.get_descriptor()}",
                                        f"{method.get_class_name()}->"
                                        f"{method.get_name()}{method.get_descriptor()}"
                                        " --> "
                                        "Landroid/webkit/SslErrorHandler;->proceed()V",
                                    )

                            if not found_proceed:
                                if self.analyze_method_rec(
                                    dx, method, actual_depth=0, depth=3
                                ):
                                    vulnerable_methods[method.get_class_name()] = (
                                        f"{method.get_name()}{method.get_descriptor()}",
                                        f"{method.get_class_name()}->"
                                        f"{method.get_name()}{method.get_descriptor()}"
                                        " --> "
                                        "Landroid/webkit/SslErrorHandler;->proceed()V",
                                    )

            for key, value in vulnerable_methods.items():
                vulnerability_found = True
                details.code.append(vuln.VulnerableCode(value[0], key, value[1]))

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
