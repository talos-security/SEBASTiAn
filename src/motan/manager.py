#!/usr/bin/env python3

import logging
import os

from yapsy.PluginManager import PluginManager

from motan import categories


class AndroidVulnerabilityManager(object):
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Collect all the vulnerability checks contained in the
        # ./android_vulnerabilities directory. Each vulnerability has an associated
        # .vulnerability file with some metadata and belongs to at least a category
        # (see the base class of each vulnerability).
        self.manager = PluginManager(
            directories_list=[
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "android_vulnerabilities",
                )
            ],
            plugin_info_ext="vulnerability",
            categories_filter={
                "Manifest": categories.IManifestVulnerability,
                "HybridApp": categories.IHybridAppVulnerability,
                "Code": categories.ICodeVulnerability,
            },
        )
        self.manager.collectPlugins()

    @property
    def platform(self) -> str:
        return "Android"

    def get_all_vulnerability_checks(self):
        # Order plugins alphabetically.
        return sorted(self.manager.getAllPlugins(), key=lambda x: x.name)


class IOSVulnerabilityManager(object):
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Collect all the vulnerability checks contained in the
        # ./ios_vulnerabilities directory. Each vulnerability has an associated
        # .vulnerability file with some metadata and belongs to at least a category
        # (see the base class of each vulnerability).
        self.manager = PluginManager(
            directories_list=[
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "ios_vulnerabilities"
                )
            ],
            plugin_info_ext="vulnerability",
            categories_filter={
                "Plist": categories.IPlistVulnerability,
                "Code": categories.ICodeVulnerability,
            },
        )
        self.manager.collectPlugins()

    @property
    def platform(self) -> str:
        return "iOS"

    def get_all_vulnerability_checks(self):
        # Order plugins alphabetically.
        return sorted(self.manager.getAllPlugins(), key=lambda x: x.name)
