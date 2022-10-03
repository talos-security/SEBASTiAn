#!/usr/bin/env python3

import logging
import os
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class AccessInternetWithoutPermission(categories.ICodeVulnerability):
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

            # Continue only if the internet permission is not requested by the app.
            if (
                "android.permission.INTERNET"
                not in analysis_info.get_apk_analysis().get_permissions()
            ):
                # The target classes are the ones needing internet.
                target_classes = [
                    dx.get_class_analysis("Ljava/net/URLConnection;"),
                    dx.get_class_analysis("Ljava/net/HttpURLConnection;"),
                    dx.get_class_analysis("Ljavax/net/ssl/HttpsURLConnection;"),
                    dx.get_class_analysis(
                        "Lorg/apache/http/impl/client/DefaultHttpClient;"
                    ),
                    dx.get_class_analysis("Lorg/apache/http/client/HttpClient;"),
                ]

                # No target classes were found, there is no reason to continue checking
                # this vulnerability.
                if not target_classes or not any(target_classes):
                    return None

                # The list of classes that contain the vulnerability. The key is the
                # class signature where the vulnerable code was found, while the value
                # is a tuple with the signature of the vulnerable API/other info about
                # the vulnerability and the full path leading to the vulnerability.
                vulnerable_classes = {}

                for caller_set, original in [
                    (target_class.get_xref_from(), target_class)
                    for target_class in target_classes
                    if target_class
                ]:
                    for caller_class in caller_set:

                        # Ignore excluded classes (if any).
                        if analysis_info.ignore_libs:
                            if any(
                                caller_class.name.startswith(prefix)
                                for prefix in analysis_info.ignored_classes_prefixes
                            ):
                                continue

                        vulnerable_classes[caller_class.name] = (
                            original.name,
                            f"{caller_class.name} --> {original.name}",
                        )

                for key, value in vulnerable_classes.items():
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
