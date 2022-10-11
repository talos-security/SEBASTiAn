#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.webview_javascript_interface import (
    WebViewAddJavaScriptInterface,
)


class TestWebViewAddJavaScriptInterface(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WebView-NoUserPermission-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewAddJavaScriptInterface().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewAddJavaScriptInterface.__name__
        assert len(vulnerability.code) == 2
