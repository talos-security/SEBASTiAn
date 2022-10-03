#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.bytecodes.axml import AXMLPrinter
from lxml import etree
from lxml import objectify

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class CordovaAccessOriginWithCsp(categories.IHybridAppVulnerability):
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

            # Check access issues:
            is_access_configured = False
            access_issues = []
            for item in tree.findall(".//access"):
                is_access_configured = True
                # Check if an http link or a wildcard is used.
                if "origin" in item.attrib and (
                    item.attrib["origin"].strip().startswith("http:")
                    or item.attrib["origin"].strip() == "*"
                ):
                    access_issues.append(etree.tostring(item))

            # Check CSP issues:
            content_element = tree.find("content")
            main_html_file = None
            main_html_file_content = None

            if content_element is not None and "src" in content_element.attrib:
                main_html_file = content_element.attrib["src"]

            try:
                try:
                    main_html_file_content = analysis_info.get_apk_analysis().get_file(
                        main_html_file
                    )
                except Exception:
                    main_html_file_content = analysis_info.get_apk_analysis().get_file(
                        f"assets/www/{main_html_file}"
                    )
            except Exception:
                # No html file was found, unable to check CSP.
                pass

            csp_tags = []
            if main_html_file_content:
                html_parser = etree.HTMLParser()
                html = etree.fromstring(main_html_file_content, html_parser)
                meta_tags = html.findall(".//meta")

                # Check if there are CSP policies in the html file.
                csp_tags = [
                    meta_tag
                    for meta_tag in meta_tags
                    if "http-equiv" in meta_tag.attrib
                    and meta_tag.attrib["http-equiv"].lower()
                    == "content-security-policy"
                ]

            if is_access_configured:
                # Access is configured, check if there are issues.
                if access_issues:
                    # There are access issues, check also CSP.
                    if csp_tags:
                        # Access issues, CSP configured.
                        vulnerability_found = True
                        for item in access_issues:
                            details.code.append(
                                vuln.VulnerableCode(
                                    item, "res/xml/config.xml", "res/xml/config.xml"
                                )
                            )
            else:
                # Access is not configured, check CSP.
                if csp_tags:
                    # Access not configured, CSP configured.
                    vulnerability_found = True
                    for item in access_issues:
                        details.code.append(
                            vuln.VulnerableCode(
                                item, "res/xml/config.xml", "res/xml/config.xml"
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
