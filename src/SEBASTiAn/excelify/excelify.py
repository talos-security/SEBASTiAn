#!/usr/bin/env python3

import json
import os
from typing import List

import xlsxwriter

from SEBASTiAn import vulnerability as vuln
from SEBASTiAn.manager import AndroidVulnerabilityManager, IOSVulnerabilityManager
from SEBASTiAn.vulnerability import VulnerabilityDetails, VulnerabilityReference


def export_vulnerabilities_to_excel():
    xlsx_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "xlsx")
    xlsx_file_path = os.path.join(xlsx_dir, "vulnerabilities.xlsx")

    # Make sure the directory where to save the xlsx file exists.
    if not os.path.isdir(xlsx_dir):
        os.makedirs(xlsx_dir, exist_ok=True)

    # Prepare the workbook and the styles.
    workbook = xlsxwriter.Workbook(xlsx_file_path)

    title_left = workbook.add_format(
        {
            "text_wrap": True,
            "bold": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
            "left": 2,
        }
    )
    title_middle = workbook.add_format(
        {
            "text_wrap": True,
            "bold": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
        }
    )
    title_right = workbook.add_format(
        {
            "text_wrap": True,
            "bold": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
            "right": 2,
        }
    )

    content_left = workbook.add_format(
        {
            "text_wrap": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
            "left": 2,
        }
    )
    content_middle = workbook.add_format(
        {
            "text_wrap": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
        }
    )
    content_middle_la = workbook.add_format(
        {"text_wrap": True, "align": "left", "valign": "vcenter", "bottom": 2, "top": 2}
    )
    content_right = workbook.add_format(
        {
            "text_wrap": True,
            "align": "center",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
            "right": 2,
        }
    )
    content_right_la = workbook.add_format(
        {
            "text_wrap": True,
            "align": "left",
            "valign": "vcenter",
            "bottom": 2,
            "top": 2,
            "right": 2,
        }
    )

    # Generate a worksheet for each platform and language.
    for manager in [AndroidVulnerabilityManager(), IOSVulnerabilityManager()]:
        for lang in ["en", "it"]:
            vulnerabilities: List[VulnerabilityDetails] = []

            for item in manager.get_all_vulnerability_checks():
                details = vuln.get_vulnerability_details(item.path, lang)
                details.id = item.name
                vulnerabilities.append(details)

            worksheet = workbook.add_worksheet(f"{manager.platform} | {lang}")

            worksheet.set_default_row(50)

            worksheet.set_column(0, 0, 10)
            worksheet.set_column(1, 1, 30)  # ID
            worksheet.set_column(2, 2, 35)  # Name
            worksheet.set_column(3, 3, 70)  # Description
            worksheet.set_column(4, 4, 15)  # OWASP category
            worksheet.set_column(5, 5, 60)  # Remediation
            worksheet.set_column(6, 6, 120)  # References

            # Risk data will be written only in English version.
            if lang == "en":
                worksheet.set_column(7, 7, 20)  # Attack Vector
                worksheet.set_column(8, 8, 20)  # Attack Complexity
                worksheet.set_column(9, 9, 20)  # Privileges Required
                worksheet.set_column(10, 10, 20)  # User Interaction
                worksheet.set_column(11, 11, 20)  # Scope
                worksheet.set_column(12, 12, 20)  # Confidentiality Impact
                worksheet.set_column(13, 13, 20)  # Integrity Impact
                worksheet.set_column(14, 14, 20)  # Availability Impact
                worksheet.set_column(15, 15, 20)  # Base Score

            row = 1
            col = 1

            worksheet.write(row, col, "ID", title_left)
            worksheet.write(row, col + 1, "Name", title_middle)
            worksheet.write(row, col + 2, "Description", title_middle)
            worksheet.write(row, col + 3, "OWASP MOBILE TOP 10", title_middle)
            worksheet.write(row, col + 4, "Remediation", title_middle)
            worksheet.write(
                row,
                col + 5,
                "References",
                title_middle if lang == "en" else title_right,
            )

            # Risk data will be written only in English version.
            if lang == "en":
                worksheet.write(row, col + 6, "Attack Vector", title_middle)
                worksheet.write(row, col + 7, "Attack Complexity", title_middle)
                worksheet.write(row, col + 8, "Privileges Required", title_middle)
                worksheet.write(row, col + 9, "User Interaction", title_middle)
                worksheet.write(row, col + 10, "Scope", title_middle)
                worksheet.write(row, col + 11, "Confidentiality Impact", title_middle)
                worksheet.write(row, col + 12, "Integrity Impact", title_middle)
                worksheet.write(row, col + 13, "Availability Impact", title_middle)
                worksheet.write(row, col + 14, "Base Score", title_right)

            row += 1

            for vuln_details in vulnerabilities:
                cell_values = []

                worksheet.write(row, col, vuln_details.id, content_left)
                cell_values.append(vuln_details.id)

                worksheet.write(row, col + 1, vuln_details.name, content_middle)
                cell_values.append(vuln_details.name)

                worksheet.write(
                    row, col + 2, vuln_details.description, content_middle_la
                )
                cell_values.append(vuln_details.description)

                worksheet.write(
                    row, col + 3, "\n".join(vuln_details.owasp), content_middle
                )
                cell_values.append("\n".join(vuln_details.owasp))

                worksheet.write(
                    row, col + 4, vuln_details.remediation, content_middle_la
                )
                cell_values.append(vuln_details.remediation)

                if vuln_details.references:
                    val = json.dumps(
                        json.loads(
                            VulnerabilityReference.Schema().dumps(
                                vuln_details.references
                            )
                        ),
                        indent=2,
                        ensure_ascii=False,
                    )
                    worksheet.write(
                        row,
                        col + 5,
                        val,
                        content_middle_la if lang == "en" else content_right_la,
                    )
                    cell_values.append(val)
                else:
                    worksheet.write(
                        row,
                        col + 5,
                        "",
                        content_middle_la if lang == "en" else content_right_la,
                    )

                # Risk data will be written only in English version.
                if lang == "en":
                    worksheet.write(
                        row, col + 6, vuln_details.cvss.attack_vector, content_middle
                    )
                    worksheet.write(
                        row,
                        col + 7,
                        vuln_details.cvss.attack_complexity,
                        content_middle,
                    )
                    worksheet.write(
                        row,
                        col + 8,
                        vuln_details.cvss.privileges_required,
                        content_middle,
                    )
                    worksheet.write(
                        row, col + 9, vuln_details.cvss.user_interaction, content_middle
                    )
                    worksheet.write(
                        row, col + 10, vuln_details.cvss.scope, content_middle
                    )
                    worksheet.write(
                        row,
                        col + 11,
                        vuln_details.cvss.confidentiality_impact,
                        content_middle,
                    )
                    worksheet.write(
                        row,
                        col + 12,
                        vuln_details.cvss.integrity_impact,
                        content_middle,
                    )
                    worksheet.write(
                        row,
                        col + 13,
                        vuln_details.cvss.availability_impact,
                        content_middle,
                    )
                    worksheet.write(
                        row, col + 14, vuln_details.cvss.base_score, content_right
                    )

                # Set a row height suitable to hold the content.
                max_val = 50
                for val in cell_values:
                    if not val:
                        continue
                    new_lines = val.count("\n")
                    if new_lines:
                        new_max_val = new_lines * 20
                        if new_max_val > max_val:
                            max_val = new_max_val
                    new_max_val = len(val) / 5
                    if new_max_val > max_val:
                        max_val = new_max_val

                worksheet.set_row(row, max_val)
                row += 1

    workbook.close()


if __name__ == "__main__":
    export_vulnerabilities_to_excel()
