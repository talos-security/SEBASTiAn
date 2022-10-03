#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.insecure_socket import InsecureSocket


class TestInsecureSocket(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "InsecureSSLSocket-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = InsecureSocket().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == InsecureSocket.__name__
        assert len(vulnerability.code) == 1
