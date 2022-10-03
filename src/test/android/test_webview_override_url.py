#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.webview_override_url import WebViewOverrideUrl


class TestWebViewOverrideUrl(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WebViewOverrideUrl-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewOverrideUrl().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewOverrideUrl.__name__
        assert len(vulnerability.code) == 1
