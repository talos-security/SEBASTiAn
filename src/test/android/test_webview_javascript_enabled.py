#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.webview_javascript_enabled import (
    WebViewJavaScriptEnabled,
)


class TestWebViewJavaScriptEnabled(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewJavaScriptEnabled().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewJavaScriptEnabled.__name__
        assert len(vulnerability.code) == 1

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "JavaScriptExecution-CodeInjection-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewJavaScriptEnabled().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewJavaScriptEnabled.__name__
        assert len(vulnerability.code) == 1
