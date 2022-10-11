#!/usr/bin/env python3

import logging
import math
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from typing import Optional, List, Tuple

import lief
from androguard.core.analysis.analysis import Analysis as AndroguardAnalysis
from androguard.core.androconf import is_ascii_problem
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK

from SEBASTiAn import util


class BaseAnalysis(ABC):
    """
    This base class holds the details and the internal state of a vulnerability analysis
    for a mobile application. When analyzing a new application, an instance of a child
    of this class has to be instantiated and passed to all the code checking for
    vulnerabilities (in sequence).
    """

    def __init__(self, language: str = "en"):
        self.language: str = language

        # The list of vulnerabilities already checked for this application.
        self.checked_vulnerabilities: List[str] = []

    @abstractmethod
    def initialize(self):
        # This method contains the initialization (one time) operations that could
        # generate errors. This method will be called once at the beginning of each
        # new analysis.
        raise NotImplementedError()

    @abstractmethod
    def finalize(self):
        # This method contains the instructions to be called after the analysis ends
        # (e.g., cleaning temporary files). This method will be called once at the end
        # of each new analysis.
        raise NotImplementedError()


class AndroidAnalysis(BaseAnalysis):
    def __init__(
        self,
        apk_path: str,
        language: str = "en",
        ignore_libs: bool = False,
        generate_report: bool = False,
    ):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__(language)

        self.apk_path: str = apk_path
        self.ignore_libs: bool = ignore_libs
        self.generate_report: bool = generate_report

        # The list of class prefixes to ignore during the vulnerability analysis
        # (to be used when ignore_libs parameter is True).
        self.ignored_classes_prefixes: List[str] = []

        self._apk_analysis: Optional[APK] = None
        self._dex_analysis: Optional[AndroguardAnalysis] = None
        self._native_libs: List[str] = []
        self._ascii_obfuscation_rate: float = -1
        self._short_name_obfuscation_rate: float = -1

    def initialize(self):
        self.logger.info(f"Analyzing Android application '{self.apk_path}'")

        # Check if the apk file to analyze is a valid file.
        if not os.path.isfile(self.apk_path):
            self.logger.error(f"Unable to find file '{self.apk_path}'")
            raise FileNotFoundError(f"Unable to find file '{self.apk_path}'")

        if self.ignore_libs:
            self.ignored_classes_prefixes = list(
                map(
                    lambda x: f"L{x}",  # Class names start with L.
                    util.get_libs_to_ignore(),
                )
            )

        self.perform_androguard_analysis()

    def finalize(self):
        pass

    def perform_androguard_analysis(self) -> None:
        self._apk_analysis, _, self._dex_analysis = AnalyzeAPK(self.apk_path)
        self._native_libs = [
            file_path
            for file_path, file_type in self._apk_analysis.get_files_types().items()
            if file_type.startswith("ELF ")
        ]

    def get_apk_analysis(self) -> APK:
        if not self._apk_analysis:
            self.perform_androguard_analysis()

        return self._apk_analysis

    def get_dex_analysis(self) -> AndroguardAnalysis:
        if not self._dex_analysis:
            self.perform_androguard_analysis()

        return self._dex_analysis

    def get_native_libs(self) -> List[str]:
        if not self._apk_analysis:
            # We check _apk_analysis instead of _native_libs since _native_libs could
            # be empty even after the analysis (not all apps use native libraries).
            self.perform_androguard_analysis()

        return self._native_libs

    def get_obfuscation_rates(self) -> Tuple[float, float]:
        if self._ascii_obfuscation_rate < 0 and self._short_name_obfuscation_rate < 0:
            # Ignore excluded classes (if any).
            if self.ignore_libs:
                all_classes = list(
                    clazz
                    for clazz in self.get_dex_analysis().get_internal_classes()
                    if not any(
                        clazz.name.startswith(prefix)
                        for prefix in self.ignored_classes_prefixes
                    )
                )
            else:
                all_classes = list(self.get_dex_analysis().get_internal_classes())

            # The lists are created from a set to avoid duplicates.
            all_fields = list(
                {
                    repr(field): field
                    for clazz in all_classes
                    for field in clazz.get_fields()
                }.values()
            )
            all_methods = list(
                {
                    repr(method): method
                    for clazz in all_classes
                    for method in clazz.get_methods()
                }.values()
            )

            # Non ascii class/field/method names (probably using DexGuard).

            non_ascii_class_names = list(
                filter(lambda x: is_ascii_problem(x.name), all_classes)
            )
            non_ascii_field_names = list(
                filter(lambda x: is_ascii_problem(x.name), all_fields)
            )
            non_ascii_method_names = list(
                filter(lambda x: is_ascii_problem(x.name), all_methods)
            )

            if len(all_classes) > 0:
                non_ascii_class_percentage = (
                    100 * len(non_ascii_class_names) / len(all_classes)
                )
            else:
                non_ascii_class_percentage = 0

            if len(all_fields) > 0:
                non_ascii_field_percentage = (
                    100 * len(non_ascii_field_names) / len(all_fields)
                )
            else:
                non_ascii_field_percentage = 0

            if len(all_methods) > 0:
                non_ascii_method_percentage = (
                    100 * len(non_ascii_method_names) / len(all_methods)
                )
            else:
                non_ascii_method_percentage = 0

            # Short class/field/method names (probably using ProGuard).

            # We want to find the value "N", that represents the minimum number of chars
            # needed to write as many unique names as the number of classes (the same
            # can be applied to fields and methods).

            # If the set S has BASE elements, the number of N-tuples over S is
            # CLASSES = BASE^N. We want to find N (knowing the other elements):
            # N = log_BASE_(CLASSES)
            # log_BASE_(CLASSES) = log(CLASSES) / log(BASE)
            # (when changing logarithm base)

            # BASE = 52 (26 lowercase letters + 26 uppercase letters, by default
            # ProGuard does not use numbers)
            # CLASSES = number of classes found

            BASE = 52
            CLASSES = len(all_classes)
            FIELDS = len(all_fields)
            METHODS = len(all_methods)

            if len(all_classes) > 0:
                N_CLASSES = int(math.ceil(math.log(CLASSES, BASE)))
            else:
                N_CLASSES = 0
            if len(all_fields) > 0:
                N_FIELDS = int(math.ceil(math.log(FIELDS, BASE)))
            else:
                N_FIELDS = 0
            if len(all_methods) > 0:
                N_METHODS = int(math.ceil(math.log(METHODS, BASE)))
            else:
                N_METHODS = 0

            # Function used to get the class name from full name with package.
            # Ex: com/example/name; -> name;
            def get_only_class_name(full_class):
                tokens = full_class.name.rsplit("/", 1)
                if len(tokens) == 2:
                    return tokens[1]
                else:
                    return tokens[0]

            short_class_names = list(
                filter(
                    lambda x:
                    # N_CLASSES + 1 because dex class names end with ;
                    len(get_only_class_name(x)) <= N_CLASSES + 1,
                    all_classes,
                )
            )

            short_field_names = list(
                filter(lambda x: len(x.name) <= N_FIELDS, all_fields)
            )

            short_method_names = list(
                filter(lambda x: len(x.name) <= N_METHODS, all_methods)
            )

            if len(all_classes) > 0:
                short_class_percentage = 100 * len(short_class_names) / len(all_classes)
            else:
                short_class_percentage = 0

            if len(all_fields) > 0:
                short_field_percentage = 100 * len(short_field_names) / len(all_fields)
            else:
                short_field_percentage = 0

            if len(all_methods) > 0:
                short_method_percentage = (
                    100 * len(short_method_names) / len(all_methods)
                )
            else:
                short_method_percentage = 0

            self._ascii_obfuscation_rate = max(
                [
                    non_ascii_class_percentage,
                    non_ascii_field_percentage,
                    non_ascii_method_percentage,
                ]
            )
            self._short_name_obfuscation_rate = max(
                [
                    short_class_percentage,
                    short_field_percentage,
                    short_method_percentage,
                ]
            )

        return self._ascii_obfuscation_rate, self._short_name_obfuscation_rate


class IOSAnalysis(BaseAnalysis):
    def __init__(
        self,
        ipa_path: str,
        language: str = "en",
        keep_files: bool = False,
        working_dir: str = None,
    ):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__(language)

        self.ipa_path: str = ipa_path
        self.keep_files: bool = keep_files

        # If no working directory is specified, use a temporary directory.
        if not working_dir:
            working_dir = tempfile.gettempdir()

        self.working_dir = os.path.join(working_dir, "SEBASTiAn_working_dir")

        os.makedirs(self.working_dir, exist_ok=True)

        self.bin_path = None
        self.bin_name = None
        self.bin_arch = None
        self.plist_readable = None
        self.macho_object = None
        self.macho_symbols = None

    def initialize(self):
        self.logger.info(f"Analyzing iOS application '{self.ipa_path}'")

        self.bin_path, self.plist_readable = util.unpack_ios_app(
            self.ipa_path, working_dir=self.working_dir
        )

        parsed_binary = lief.MachO.parse(
            self.bin_path, config=lief.MachO.ParserConfig.deep
        )

        if parsed_binary.size > 1:
            raise ValueError("Single architecture binary expected, fat binary found")

        self.macho_object = parsed_binary.at(0)
        self.macho_symbols = "\n".join([x.name for x in self.macho_object.symbols])

        self.bin_name = self.macho_object.name
        self.bin_arch = self.macho_object.header.cpu_type.name

    def finalize(self):
        if not self.keep_files:
            self.logger.info(
                "Deleting intermediate files generated during the iOS analysis"
            )
            shutil.rmtree(self.working_dir)
        else:
            self.logger.info(
                "Intermediate files generated during the iOS analysis "
                f"were saved in '{self.working_dir}'"
            )
