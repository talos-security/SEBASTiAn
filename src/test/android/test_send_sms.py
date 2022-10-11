#!/usr/bin/env python3

import os

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.android_vulnerabilities.send_sms import SendSms


class TestSendSms(object):
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
        vulnerability = SendSms().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == SendSms.__name__
        assert len(vulnerability.code) == 1
