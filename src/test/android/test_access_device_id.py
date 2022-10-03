#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.access_device_id import AccessDeviceId


class TestAccessDeviceId(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            os.path.pardir,
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        analysis.initialize()
        vulnerability = AccessDeviceId().check_vulnerability(analysis)
        analysis.finalize()

        assert vulnerability.id == AccessDeviceId.__name__
        assert len(vulnerability.code) == 1
