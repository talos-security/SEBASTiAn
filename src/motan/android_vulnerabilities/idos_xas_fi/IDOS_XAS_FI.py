#!/usr/bin/env python3
import glob
import logging
import os
import shutil
import subprocess
from typing import Optional, List
import platform
from shlex import split as sh_split
import subprocess
import json

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.taint_analysis import TaintAnalysis


def append_vulnerabilities(vulnerability_type, vuln_list, details):
    for file in vuln_list:
        with open(file, "r") as f:
            IDOS_data = json.load(f)
            for item in IDOS_data:
                details.code.append(
                    vuln.VulnerableCode(
                        vulnerability_type, item["stmt"], item["method"]
                    )
                )


class IDOS_XAS_FI(categories.ICodeVulnerability):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)

    def check_vulnerability(
        self, analysis_info: AndroidAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:

        try:
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")
            apk_path = analysis_info.apk_path
            APK = analysis_info.get_apk_analysis()
            package = APK.get_package()
            android_jar_path = os.environ.get("ANDROID_JAR_PATH")
            temp_dir = os.environ.get(
                "IDOS_XAS_FI_TEMP_DIR",
                os.path.abspath("./results/IDOS_XAS_FI_TEMP_DIR"),
            )
            results = os.environ.get(
                "IDOS_XAS_FI_RESULTS_DIR",
                os.path.abspath("./results/IDOS_XAS_FI_RESULTS_DIR"),
            )

            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(results, exist_ok=True)

            if android_jar_path is None:
                platform_name = platform.system()
                if platform_name == "Linux":
                    android_jar_path = "/usr/lib/android-sdk/platforms/"
                elif platform_name == "Windows":
                    android_jar_path = (
                        "C:\\Program Files\\Android\\android-sdk\\platforms\\"
                    )
                elif platform_name == "Darwin":
                    android_jar_path = f"/Users/{os.environ.get('USER')}/Library/Android/sdk/platforms/"

            jar_file = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "SootAndro-2.8.jar"
            )
            java_comand = sh_split(
                f"java -jar {jar_file} {package} {apk_path} {android_jar_path}"
            )

            subprocess.call(
                java_comand,
                timeout=1000,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            IDOS_json = glob.glob(f"{temp_dir}{os.sep}IDOS{os.sep}*.json")
            XAS_json = glob.glob(f"{temp_dir}{os.sep}XAS{os.sep}*.json")
            FI_json = glob.glob(f"{temp_dir}{os.sep}FI{os.sep}*.json")

            append_vulnerabilities("IDOS", IDOS_json, details)
            append_vulnerabilities("XAS", XAS_json, details)
            append_vulnerabilities("FI", FI_json, details)

            # Generate a folder with the app vulnerabilities
            if analysis_info.generate_report:
                apk_name = os.path.basename(os.path.splitext(apk_path)[0])
                # os.makedirs(f"results{os.sep}{apk_name}", exist_ok=True)
                shutil.copytree(temp_dir, f"{results}{os.sep}{apk_name}")
            subprocess.call(f"rm -rf {temp_dir}/*", shell=True)

            if len(IDOS_json) > 0 or len(XAS_json) > 0 or len(FI_json) > 0:
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
