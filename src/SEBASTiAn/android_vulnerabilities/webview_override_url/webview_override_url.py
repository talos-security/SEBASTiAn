#!/usr/bin/env python3

import logging
import os
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.taint_analysis import RegisterAnalyzer


class WebViewOverrideUrl(categories.ICodeVulnerability):
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

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # a tuple with the signature of the vulnerable API/other info about the
            # vulnerability and the full path leading to the vulnerability.
            vulnerable_methods = {}

            # Look for subclasses of WebViewClient and check shouldOverrideUrlLoading
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

                    method_found = False
                    for method in clazz.get_vm_class().get_methods():
                        for target_name, target_descriptor in [
                            (
                                "shouldOverrideUrlLoading",
                                "(Landroid/webkit/WebView; Ljava/lang/String;)Z",
                            ),
                            (
                                "shouldOverrideUrlLoading",
                                "(Landroid/webkit/WebView; "
                                "Landroid/webkit/WebResourceRequest;)Z",
                            ),
                        ]:
                            if (
                                method.name == target_name
                                and method.descriptor == target_descriptor
                            ):
                                method_found = True

                                register_analyzer = RegisterAnalyzer(
                                    analysis_info.get_apk_analysis(),
                                    analysis_info.get_dex_analysis(),
                                )
                                register_analyzer.load_instructions(
                                    method.get_instructions()
                                )
                                results = (
                                    register_analyzer.get_all_possible_return_values()
                                )

                                # 0 means that false was returned.
                                result_false = False
                                for result in results:
                                    if result == 0:
                                        result_false = True

                                if result_false:
                                    vulnerable_methods[method.get_class_name()] = (
                                        f"{method.get_name()}{method.get_descriptor()}",
                                        f"{method.get_class_name()}->"
                                        f"{method.get_name()}{method.get_descriptor()}",
                                    )

                    if not method_found:
                        # shouldOverrideUrlLoading returns false by default.
                        vulnerable_methods[clazz.name] = (
                            "shouldOverrideUrlLoading not overridden, returns false "
                            "by default",
                            f"{clazz.name}",
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
