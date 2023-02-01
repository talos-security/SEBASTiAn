#!/usr/bin/env python3

import logging
import os
import plistlib
import re
import zipfile
from typing import Iterable, List

import lief
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import ClassDefItem
from biplist import readPlist

logger = logging.getLogger(__name__)


def get_non_empty_lines_from_file(file_name: str) -> List[str]:
    try:
        with open(file_name, "r", encoding="utf-8") as file:
            # Return a list with the non blank lines contained in the file.
            return list(filter(None, (line.rstrip() for line in file)))
    except Exception as e:
        logger.error(f"Error when reading file '{file_name}': {e}")
        raise


# Adapted from https://github.com/pkumza/LiteRadar
def get_libs_to_ignore() -> List[str]:
    return get_non_empty_lines_from_file(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "resources",
            "android_libs_to_ignore.txt",
        )
    )


def check_valid_apk_file(input_file: str):
    try:
        valid_apk = APK(input_file).is_valid_APK()
    except Exception:
        valid_apk = False

    if not valid_apk:
        raise ValueError("This file is not a valid apk file")


def check_valid_ipa_file(input_file: str):
    try:
        with zipfile.ZipFile(input_file, "r") as ipa_zip:
            info_plist_file_regex = re.compile(
                r"Payload/.+\.app/info\.plist", re.IGNORECASE
            )

            # Every valid ipa application has an info.plist file.
            info_plist_path = list(
                filter(info_plist_file_regex.match, ipa_zip.namelist())
            )[0]

            with ipa_zip.open(info_plist_path, "r") as info_plist_file:
                plistlib.load(info_plist_file)

    except Exception:
        raise ValueError("This file is not a valid ipa file")


def is_class_implementing_interfaces(clazz: ClassDefItem, interfaces: Iterable[str]):
    """
    Check if a class is implementing a specific list of interfaces.
    """
    return all(interface in clazz.get_interfaces() for interface in interfaces)


def unpack_ios_app(ipa_path: str, working_dir: str):
    bin_name = ""
    bin_path = None
    plist_readable = {}

    with zipfile.ZipFile(ipa_path, "r") as zipfile_ipa:
        # Look for the Info.plist file and find the binary name (CFBundleExecutable).
        for entry in zipfile_ipa.infolist():
            normpath = os.path.normpath(entry.filename)
            file_split = normpath.split(os.sep)

            if (
                len(file_split) == 3
                and file_split[0] == "Payload"
                and file_split[1].endswith(".app")
                and file_split[2].lower() == "info.plist"
            ):
                name_subdir = file_split[1].split(".app")[0]
                output_dir = os.path.join(working_dir, name_subdir)
                os.makedirs(output_dir, exist_ok=True)

                read_content_plist = zipfile_ipa.read(entry)

                with open(os.path.join(output_dir, "Info.plist"), "wb+") as plist:
                    plist.write(read_content_plist)

                plist_readable = readPlist(os.path.join(output_dir, "Info.plist"))
                bin_name = plist_readable.get("CFBundleExecutable", "")
                break

        # Get the binary file, preferably for arm64 architecture.
        for entry in zipfile_ipa.infolist():
            normpath = os.path.normpath(entry.filename)
            file_split = normpath.split(os.sep)

            # encode("cp437") is used because of
            # https://github.com/python/cpython/blob/a993e901ebe60c38d46ecb31f771d0b4a206828c/Lib/zipfile.py#L1358-L1363
            if (
                len(file_split) == 3
                and file_split[0] == "Payload"
                and file_split[1].endswith(".app")
                and (
                    file_split[2] == bin_name
                    or file_split[2].encode("cp437") == bin_name.encode()
                )
            ):
                name_subdir = file_split[1].split(".app")[0]
                output_dir = os.path.join(working_dir, name_subdir)
                os.makedirs(output_dir, exist_ok=True)

                binary_from_zip = zipfile_ipa.read(entry)
                bin_path = os.path.join(output_dir, name_subdir)
                with open(bin_path, "wb") as binary_output:
                    binary_output.write(binary_from_zip)

                # NOTE: lipo can also be used to extract the binary from the universal
                # binary, but cannot be used on Windows and requires to install
                # additional tools on Linux.

                fat_binary = lief.MachO.parse(
                    bin_path, config=lief.MachO.ParserConfig.quick
                )

                for binary in fat_binary:
                    if binary.header.cpu_type == lief.MachO.CPU_TYPES.ARM64:
                        # Overwrite the fat binary with the binary for arm64.
                        binary.write(bin_path)
                        break
                else:
                    # arm64 binary not available, take the first one available.
                    fat_binary.at(0).write(bin_path)

                break

    if bin_path:
        return bin_path, plist_readable
    else:
        logger.error("No binary file found inside the iOS app")

    return None, None
