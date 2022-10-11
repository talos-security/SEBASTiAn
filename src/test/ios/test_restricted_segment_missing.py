#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import IOSAnalysis
from SEBASTiAn.ios_vulnerabilities.restricted_segment_missing import (
    RestrictedSegmentMissing,
)


class TestRestrictedSegmentMissing(object):
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
        vulnerability = RestrictedSegmentMissing().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == RestrictedSegmentMissing.__name__
        assert len(vulnerability.code) == 0
