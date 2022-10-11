#!/usr/bin/env python3

import logging
import os
from typing import Optional

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis


class ExportedComponent(categories.IManifestVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    # noinspection PyProtectedMember
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

            apk = analysis_info.get_apk_analysis()

            # Look for exported components and check their permissions.
            for tag in [
                "activity",
                "activity-alias",
                "service",
                "receiver",
                "provider",
            ]:
                for item in apk.find_tags(tag):
                    name = item.get(apk._ns("name"), "")
                    exported = item.get(apk._ns("exported"), "")
                    permission = item.get(apk._ns("permission"), "")

                    # Check only components where the exported attribute is not set to
                    # false explicitly.
                    if name.strip() and exported.lower() != "false":
                        to_check = False
                        is_launcher = False
                        has_actions_in_intent_filter = False
                        for intent in item.findall("./intent-filter"):
                            for action in intent.findall("./action"):
                                # Ignore Google actions.
                                if not action.get(apk._ns("name"), "").startswith(
                                    ("android.", "com.android.")
                                ):
                                    has_actions_in_intent_filter = True
                            for category in intent.findall("./category"):
                                if (
                                    category.get(apk._ns("name"))
                                    == "android.intent.category.LAUNCHER"
                                ):
                                    is_launcher = True

                        # Exported attribute is not set explicitly, but the component
                        # has intent filters (so the component is exported).
                        if exported == "" and has_actions_in_intent_filter:
                            to_check = True

                        # Exported attribute is set to True explicitly.
                        if exported.lower() == "true":
                            to_check = True

                        if not is_launcher and to_check:
                            accessible = False
                            if not permission:
                                # Exported, without any permission set.
                                accessible = True
                            else:
                                # Exported, with permission set.
                                detail = apk.get_declared_permissions_details().get(
                                    permission
                                )
                                if detail:
                                    level = detail["protectionLevel"]
                                    if level == "None":
                                        level = None
                                    if (
                                        level
                                        and (
                                            int(level, 16) == 0x0
                                            or int(level, 16) == 0x1
                                        )
                                    ) or not level:
                                        # 0x0 is normal protectionLevel,
                                        # 0x1 is dangerous protectionLevel
                                        # (protectionLevel is set to normal by
                                        # default).
                                        accessible = True
                                else:
                                    detail = apk.get_details_permissions().get(
                                        permission
                                    )
                                    if detail:
                                        level = detail[0].lower()
                                        if level == "normal" or level == "dangerous":
                                            accessible = True

                            if accessible:
                                vulnerability_found = True
                                details.code.append(
                                    vuln.VulnerableCode(
                                        f'exported {tag} "{name}"',
                                        "AndroidManifest.xml",
                                        "AndroidManifest.xml",
                                    )
                                )

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
