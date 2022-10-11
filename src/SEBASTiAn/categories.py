#!/usr/bin/env python3

from abc import ABC, abstractmethod
from typing import Optional

from yapsy.IPlugin import IPlugin

from SEBASTiAn.analysis import BaseAnalysis
from SEBASTiAn.vulnerability import VulnerabilityDetails


class IBaseVulnerability(ABC, IPlugin):
    @abstractmethod
    def check_vulnerability(
        self, analysis_info: BaseAnalysis
    ) -> Optional[VulnerabilityDetails]:
        raise NotImplementedError()


class IManifestVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(
        self, analysis_info: BaseAnalysis
    ) -> Optional[VulnerabilityDetails]:
        raise NotImplementedError()


class IPlistVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(
        self, analysis_info: BaseAnalysis
    ) -> Optional[VulnerabilityDetails]:
        raise NotImplementedError()


class IHybridAppVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(
        self, analysis_info: BaseAnalysis
    ) -> Optional[VulnerabilityDetails]:
        raise NotImplementedError()


class ICodeVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(
        self, analysis_info: BaseAnalysis
    ) -> Optional[VulnerabilityDetails]:
        raise NotImplementedError()
