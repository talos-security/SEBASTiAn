#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.crypto_constant_key import CryptoConstantKey


class TestCryptoConstantKey(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "ConstantKey-ForgeryAttack-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = CryptoConstantKey().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == CryptoConstantKey.__name__
        assert len(vulnerability.code) == 2

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "BlockCipher-NonRandomIV-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = CryptoConstantKey().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == CryptoConstantKey.__name__
        assert len(vulnerability.code) == 1
