#!/usr/bin/env python3

import os

from motan.analysis import IOSAnalysis
from motan.ios_vulnerabilities.insecure_api import InsecureAPI


class TestInsecureApi(object):
    def test_existing_vulnerability(self):
        ipa_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "iGoat",
            "iGoat-Swift.ipa",
        )

        analysis = IOSAnalysis(ipa_path)
        analysis.initialize()
        vulnerability = InsecureAPI().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == InsecureAPI.__name__
        assert len(vulnerability.code) == 1
