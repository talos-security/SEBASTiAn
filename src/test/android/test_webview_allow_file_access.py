#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.webview_allow_file_access import (
    WebViewAllowFileAccess,
)


class TestWebViewAllowFileAccess(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "SEBASTiAn-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewAllowFileAccess().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewAllowFileAccess.__name__
        assert len(vulnerability.code) == 1

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "InsecureBankv2",
            "InsecureBankv2.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewAllowFileAccess().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewAllowFileAccess.__name__
        assert len(vulnerability.code) == 1
