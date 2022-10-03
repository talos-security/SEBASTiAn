#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.crypto_keystore_entry_without_password import (
    CryptoKeystoreEntryWithoutPassword,
)


class TestCryptoConstantKey(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "ExposedCredentials-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = CryptoKeystoreEntryWithoutPassword().check_vulnerability(
            analysis
        )
        analysis.finalize()

        assert vulnerability.id == CryptoKeystoreEntryWithoutPassword.__name__
        assert len(vulnerability.code) == 1
