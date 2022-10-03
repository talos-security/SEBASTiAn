#!/usr/bin/env python3

import logging
import os
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class SystemPermissionUsage(categories.IManifestVulnerability):
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

            # List of permissions not for use by third-party applications. Taken from
            # https://developer.android.com/reference/android/Manifest.permission
            system_permissions = [
                "android.permission.ACCESS_CHECKIN_PROPERTIES",
                "android.permission.ACCOUNT_MANAGER",
                "android.permission.BIND_APPWIDGET",
                "android.permission.BLUETOOTH_PRIVILEGED",
                "android.permission.BROADCAST_PACKAGE_REMOVED",
                "android.permission.BROADCAST_SMS",
                "android.permission.BROADCAST_WAP_PUSH",
                "android.permission.CALL_PRIVILEGED",
                "android.permission.CAPTURE_AUDIO_OUTPUT",
                "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
                "android.permission.CONTROL_LOCATION_UPDATES",
                "android.permission.DELETE_PACKAGES",
                "android.permission.DIAGNOSTIC",
                "android.permission.DUMP",
                "android.permission.FACTORY_TEST",
                "android.permission.INSTALL_LOCATION_PROVIDER",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.LOCATION_HARDWARE",
                "android.permission.MASTER_CLEAR",
                "android.permission.MEDIA_CONTENT_CONTROL",
                "android.permission.MODIFY_PHONE_STATE",
                "android.permission.MOUNT_FORMAT_FILESYSTEMS",
                "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                "android.permission.READ_INPUT_STATE",
                "android.permission.READ_LOGS",
                "android.permission.REBOOT",
                "android.permission.SEND_RESPOND_VIA_MESSAGE",
                "android.permission.SET_ALWAYS_FINISH",
                "android.permission.SET_ANIMATION_SCALE",
                "android.permission.SET_DEBUG_APP",
                "android.permission.SET_PROCESS_LIMIT",
                "android.permission.SET_TIME",
                "android.permission.SET_TIME_ZONE",
                "android.permission.SIGNAL_PERSISTENT_PROCESSES",
                "android.permission.STATUS_BAR",
                "android.permission.UPDATE_DEVICE_STATS",
                "android.permission.WRITE_APN_SETTINGS",
                "android.permission.WRITE_GSERVICES",
                "android.permission.WRITE_SECURE_SETTINGS",
            ]

            for perm in set(analysis_info.get_apk_analysis().get_permissions()):
                if perm in system_permissions:
                    vulnerability_found = True
                    details.code.append(
                        vuln.VulnerableCode(
                            perm, "AndroidManifest.xml", "AndroidManifest.xml"
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
