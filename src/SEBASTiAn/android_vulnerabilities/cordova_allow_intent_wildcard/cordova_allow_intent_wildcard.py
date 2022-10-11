#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.bytecodes.axml import AXMLPrinter
from lxml import etree
from lxml import objectify

import SEBASTiAn.categories as categories
from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.analysis import AndroidAnalysis


class CordovaAllowIntentWildcard(categories.IHybridAppVulnerability):
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

            try:
                # Extract and parse the Cordova configuration xml file.
                cordova_config_xml = AXMLPrinter(
                    analysis_info.get_apk_analysis().get_file("res/xml/config.xml")
                )
                parser = etree.XMLParser(recover=True)
                tree = etree.fromstring(cordova_config_xml.get_buff(), parser)
                # Remove namespace prefixes.
                for element in tree.getiterator():
                    element.tag = etree.QName(element).localname
                objectify.deannotate(tree, xsi_nil=True, cleanup_namespaces=True)
            except Exception:
                # Unable to extract Cordova configuration file, there is no reason to
                # continue checking this vulnerability.
                return None

            # Check allow-intent issues:
            for item in tree.findall(".//allow-intent"):
                if "href" in item.attrib and (
                    item.attrib["href"].strip().startswith("http:")
                    or item.attrib["href"].strip() == "*"
                ):
                    vulnerability_found = True
                    details.code.append(
                        vuln.VulnerableCode(
                            etree.tostring(item),
                            "res/xml/config.xml",
                            "res/xml/config.xml",
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
