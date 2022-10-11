#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.obfuscation_missing import ObfuscationMissing


class TestObfuscationMissing(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "SEBASTiAn-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = ObfuscationMissing().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == ObfuscationMissing.__name__
        assert len(vulnerability.code) == 1
