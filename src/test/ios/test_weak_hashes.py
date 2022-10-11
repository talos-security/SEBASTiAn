#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import IOSAnalysis
from SEBASTiAn.ios_vulnerabilities.weak_hashes import WeakHashes


class TestWeakHashes(object):
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
        vulnerability = WeakHashes().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WeakHashes.__name__
        assert len(vulnerability.code) == 1
