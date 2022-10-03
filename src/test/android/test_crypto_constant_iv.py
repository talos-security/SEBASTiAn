#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.crypto_constant_iv import CryptoConstantIv


class TestCryptoConstantIv(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "BlockCipher-NonRandomIV-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = CryptoConstantIv().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == CryptoConstantIv.__name__
        assert len(vulnerability.code) == 1
