#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import IOSAnalysis
from SEBASTiAn.ios_vulnerabilities.rpath_set import RPathSet


class TestRPathSet(object):
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
        vulnerability = RPathSet().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability is not None 
        #assert vulnerability.id == RPathSet.__name__
        assert len(vulnerability.code) == 0
