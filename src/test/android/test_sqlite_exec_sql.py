#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.sqlite_exec_sql import SqliteExecSql


class TestSqliteExecSql(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "SQLite-execSQL-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = SqliteExecSql().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == SqliteExecSql.__name__
        assert len(vulnerability.code) == 4
