#!/usr/bin/env python3

import json
import os

import xlrd

from SEBASTiAn.manager import AndroidVulnerabilityManager, IOSVulnerabilityManager
from SEBASTiAn.vulnerability import VulnerabilityDetails


def update_vulnerabilities_from_excel():
    xlsx_file_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "xlsx", "vulnerabilities.xlsx"
    )

    if not os.path.isfile(xlsx_file_path):
        raise FileNotFoundError(
            f"Cannot update vulnerabilities. File not found: '{xlsx_file_path}'"
        )

    workbook = xlrd.open_workbook(xlsx_file_path)

    # Update all platforms and languages.
    for manager in [AndroidVulnerabilityManager(), IOSVulnerabilityManager()]:
        for lang in ["en", "it"]:
            worksheet = workbook.sheet_by_name(f"{manager.platform} | {lang}")

            xlsx_vulnerabilities = []

            for row_num in range(2, worksheet.nrows):
                row_values = worksheet.row_values(row_num)

                vuln_dict = {
                    "id": row_values[1],
                    "name": row_values[2],
                    "description": row_values[3],
                    "owasp": str(row_values[4]).split("\n"),
                }
                if row_values[5]:
                    vuln_dict["remediation"] = row_values[5]
                if row_values[6]:
                    vuln_dict["references"] = json.loads(row_values[6])

                # Risk data is present only in English version.
                if lang == "en":
                    vuln_dict["cvss"] = {
                        "attack_vector": row_values[7],
                        "attack_complexity": row_values[8],
                        "privileges_required": row_values[9],
                        "user_interaction": row_values[10],
                        "scope": row_values[11],
                        "confidentiality_impact": row_values[12],
                        "integrity_impact": row_values[13],
                        "availability_impact": row_values[14],
                    }

                    # Used to validate data.
                    VulnerabilityDetails.Schema().load(vuln_dict)

                # Vulnerability data parsed correctly, add it to the list.
                xlsx_vulnerabilities.append(vuln_dict)

            for item in manager.get_all_vulnerability_checks():
                for v in xlsx_vulnerabilities:
                    if v["id"] == item.name:
                        details_path = os.path.join(item.path, f"details_{lang}.json")
                        risk_path = os.path.join(item.path, "risk.json")

                        with open(details_path, "w", encoding="utf-8") as details_file:
                            details_file.write(
                                json.dumps(
                                    {
                                        k: val
                                        for k, val in v.items()
                                        if k
                                        in [
                                            "name",
                                            "description",
                                            "remediation",
                                            "references",
                                        ]
                                    },
                                    indent=2,
                                    ensure_ascii=False,
                                )
                            )
                            details_file.write("\n")

                        # Risk data is present only in English version.
                        if lang == "en":
                            with open(risk_path, "w", encoding="utf-8") as risk_file:
                                risk_file.write(
                                    json.dumps(
                                        {
                                            k: val
                                            for k, val in v.items()
                                            if k in ["owasp", "cvss"]
                                        },
                                        indent=2,
                                        ensure_ascii=False,
                                    )
                                )
                                risk_file.write("\n")

                        break
                else:
                    raise Exception(
                        f"Can't update '{item.name}': vulnerability not found"
                    )


if __name__ == "__main__":
    update_vulnerabilities_from_excel()
