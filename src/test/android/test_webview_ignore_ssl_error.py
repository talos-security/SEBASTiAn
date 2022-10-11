#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.webview_ignore_ssl_error import (
    WebViewIgnoreSslError,
)


class TestWebViewIgnoreSslError(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WebViewIgnoreSSLWarning-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = WebViewIgnoreSslError().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == WebViewIgnoreSslError.__name__
        assert len(vulnerability.code) == 1
