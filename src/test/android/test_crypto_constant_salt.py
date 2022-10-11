#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.crypto_constant_salt import CryptoConstantSalt


class TestCryptoConstantSalt(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "PBE-ConstantSalt-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = CryptoConstantSalt().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == CryptoConstantSalt.__name__
        assert len(vulnerability.code) == 1
