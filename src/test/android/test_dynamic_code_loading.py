#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.dynamic_code_loading import DynamicCodeLoading


class TestDynamicCodeLoading(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "SEBASTiAn-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = DynamicCodeLoading().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == DynamicCodeLoading.__name__
        assert len(vulnerability.code) == 1
