#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.webview_intercept_request import (
    WebViewInterceptRequest,
)


class TestWebViewInterceptRequest(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WebViewInterceptRequest-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewInterceptRequest().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewInterceptRequest.__name__
        assert len(vulnerability.code) == 1
