#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import IOSAnalysis
from SEBASTiAn.ios_vulnerabilities.insecure_random import InsecureRandom


class TestInsecureRandom(object):
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
        vulnerability = InsecureRandom().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == InsecureRandom.__name__
        assert len(vulnerability.code) == 1
