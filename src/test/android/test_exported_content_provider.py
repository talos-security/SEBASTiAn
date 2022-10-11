#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.exported_content_provider import (
    ExportedContentProvider,
)


class TestExportedContentProvider(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "InsecureBankv2",
            "InsecureBankv2.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = ExportedContentProvider().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == ExportedContentProvider.__name__
        assert len(vulnerability.code) == 1

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WeakPermission-UnauthorizedAccess-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = ExportedContentProvider().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == ExportedContentProvider.__name__
        assert len(vulnerability.code) == 1
