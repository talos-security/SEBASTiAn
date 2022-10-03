#!/usr/bin/env python3

import os

from motan.analysis import IOSAnalysis
from motan.ios_vulnerabilities.malloc_function import MallocFunction


class TestMallocFunction(object):
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
        vulnerability = MallocFunction().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == MallocFunction.__name__
        assert len(vulnerability.code) == 0
