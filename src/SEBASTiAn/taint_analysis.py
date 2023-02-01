#!/usr/bin/env python3

import logging
from abc import ABC, abstractmethod
from typing import Optional, Union, Iterable, List

import networkx as nx
from androguard.core.analysis.analysis import (
    Analysis as AndroguardAnalysis,
    MethodAnalysis,
)
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import Instruction, EncodedMethod
from androguard.core.bytecodes.dvm_types import Operand

from SEBASTiAn.analysis import AndroidAnalysis
from SEBASTiAn.vulnerability import VulnerableCode


class Stack:
    def __init__(self):
        self._elements = []

    def __len__(self):
        return len(self._elements)

    def push(self, elem):
        self._elements.append(elem)

    def get(self):
        return self._elements[-1]

    def getAll(self):
        return self._elements


class ClassContainer(object):
    def __init__(self, class_name: str):
        self._class_name = class_name

    def get_class_name(self):
        return self._class_name

    def __repr__(self):
        return f"<{self.__class__.__name__} {self._class_name}>"


class VariableContainer(object):
    def __init__(self, full_name: str):
        self._full_name = full_name

    def get_full_name(self):
        return self._full_name

    def __repr__(self):
        return f"<{self.__class__.__name__} {self._full_name}>"


class RegisterAnalyzer(object):
    def __init__(
        self,
        apk_analysis: Optional[APK] = None,
        dex_analysis: Optional[AndroguardAnalysis] = None,
    ):
        self._register_values = {}
        self._execution_stack = Stack()
        self._apk_analysis = apk_analysis
        self._dex_analysis = dex_analysis

    def _execute_instruction(self, instruction: Instruction):
        op_code: int = instruction.get_op_value()
        operands: List[tuple] = instruction.get_operands()
        if operands:
            # [const], [const/xx], [const-string]
            if 0x12 <= op_code <= 0x1C:
                destination_register = operands[0]
                value_for_register = operands[1]
                if destination_register[0] == Operand.REGISTER:
                    destination_register_num = destination_register[1]

                    # The actual value is the last one in value_for_register.
                    immediate_value = value_for_register[-1]
                    self._register_values[destination_register_num] = immediate_value

            # [move], [move/from]
            elif 0x01 <= op_code <= 0x02:
                # The content of one register is moved to another register.
                destination_register = operands[0]
                source_register = operands[1]
                if (
                    destination_register[0] == Operand.REGISTER
                    and source_register[0] == Operand.REGISTER
                ):
                    # Get the value from the other register (if available).
                    self._register_values[
                        destination_register[1]
                    ] = self._register_values.get(source_register[1])

            # [move-result], [move-result-wide], [move-result-object], [move-exception]
            elif 0x0A <= op_code <= 0x0D:
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                # In some cases, however, the value can be retrieved.
                last_instr = self._execution_stack.get()

                if (
                    last_instr[0] == 0x6E
                    and last_instr[1][-1][2]
                    == "Landroid/content/res/Resources;->getString(I)Ljava/lang/String;"
                ):
                    # Check if the last instruction was accessing a string from
                    # resources. 0x6E is an invoke-virtual instruction.
                    string_id = self._register_values.get(last_instr[1][1][1], None)
                    try:
                        res = self._apk_analysis.get_android_resources()
                        # The string corresponding to the id was retrieved from the
                        # resources, save its value into the corresponding register.
                        self._register_values[
                            register_number
                        ] = res.get_resolved_res_configs(string_id)[0][1]
                    except Exception:
                        pass

                elif last_instr[0] == 0x6E and (
                    last_instr[1][-1][2] == "Ljava/lang/String;->getBytes()[B"
                    or last_instr[1][-1][2] == "Ljava/lang/String;->toCharArray()[C"
                ):
                    # Check if the last instruction is converting a string into bytes or
                    # into a char array. If so, keep the value of string saved in the
                    # corresponding register. 0x6E is an invoke-virtual instruction.
                    self._register_values[register_number] = self._register_values.get(
                        last_instr[1][0][1], None
                    )

                else:
                    # The value comes from an operation whose value is known only at
                    # runtime.
                    self._register_values[register_number] = None

            # [aget], [aget-xx]
            elif 0x44 <= op_code <= 0x4A:
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                self._register_values[register_number] = None

            # [iget], [iget-xx], [sget], [sget-xx]
            elif (0x52 <= op_code <= 0x58) or (0x60 <= op_code <= 0x66):
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime
                # (unless the field is constant), however we can save the field name
                # (which sometimes is a known constant value). The field name is the
                # last value.
                full_field_name = operands[-1][2]
                self._register_values[register_number] = VariableContainer(
                    full_field_name
                )

                class_name = full_field_name.split("->")[0]
                field_name = full_field_name.split("->")[1].split(" ")[0]
                field_type = full_field_name.split("->")[1].split(" ")[1]

                is_static_or_final_field = False
                clazz = self._dex_analysis.get_class_analysis(class_name)
                if clazz:
                    # Try to get the value of the field (if it's declared inline).
                    for f in clazz.get_fields():
                        field = f.get_field()
                        if (
                            field.get_name() == field_name
                            and field.get_descriptor() == field_type
                        ):
                            is_static_or_final_field = (
                                "static" in field.get_access_flags_string()
                                or "final" in field.get_access_flags_string()
                            )
                            if is_static_or_final_field:
                                self._register_values[
                                    register_number
                                ] = field.get_init_value()
                            break

                    # Check the constructor of the class containing the field, if the
                    # field is static/final then its value might be initialized there.
                    if is_static_or_final_field:
                        for m in clazz.get_methods():
                            method = m.get_method()
                            if (
                                method.get_name() == "<init>"
                                or method.get_name() == "<clinit>"
                            ) and method.get_descriptor() == "()V":
                                off = 0
                                get_instr_found = False
                                for i in method.get_instructions():
                                    if i.get_output().endswith(
                                        full_field_name
                                    ) and i.get_name().startswith("sget"):
                                        get_instr_found = True
                                    if i.get_output().endswith(
                                        full_field_name
                                    ) and i.get_name().startswith("sput"):
                                        if get_instr_found:
                                            # A sget-xx instruction was found before
                                            # this, continuing would generate an
                                            # infinite recursion.
                                            break

                                        # sput-xx instruction writes a value into the
                                        # field.
                                        ra = RegisterAnalyzer(
                                            self._apk_analysis, self._dex_analysis
                                        )
                                        ra.load_instructions(
                                            method.get_instructions(), off
                                        )
                                        self._register_values[
                                            register_number
                                        ] = ra.get_last_instruction_values()[0]
                                    off += i.get_length()

            # [new-instance]
            elif op_code == 0x22:
                register_number = operands[0][1]
                new_instance_class_name = operands[1][2]
                self._register_values[register_number] = ClassContainer(
                    new_instance_class_name
                )

        # Push op code and operands. Format: <const/4 v5, 1> is saved as
        # <[18, [(0, 5), (1, 1)]]>.
        self._execution_stack.push([op_code, operands])

    def load_instructions(
        self,
        instructions_to_execute: Iterable[Instruction],
        max_num_of_instructions: int = -1,
    ):
        """
        Virtually execute a list of instructions.

        When a list of instructions is passed to this method (e.g., the list of
        instructions from a method, by using method.get_instructions()), the
        instructions are virtually executed (until a maximum of max_num_of_instructions)
        and the values of the registers are saved (when possible). This way, when
        reaching a specific instruction, it's possible to see the values of the
        registers at that specific moment (if those values are constant).

        :param instructions_to_execute: The list of instructions to be virtually
                                        executed.
        :param max_num_of_instructions: The maximum number of instructions to be
                                        virtually executed (the instructions beyond this
                                        number will be ignored). Use -1 to virtually
                                        execute all the instructions.
        """
        offset = 0
        for index, instruction in enumerate(instructions_to_execute):
            self._execute_instruction(instruction)
            if max_num_of_instructions == -1:
                # Load all instructions.
                continue
            else:
                # Load instructions until max_num_of_instructions.
                offset += instruction.get_length()
                if offset > max_num_of_instructions:
                    break

    def initialize_register_value(self, register_num: int, register_val):
        if register_num not in self._register_values:
            self._register_values[register_num] = register_val
        else:
            raise ValueError("Register already initialized")

    def get_return_value(self):
        """
        If the last instruction in the stack is a return instruction, get the return
        value (if available).

        :return: The return value (if available, None otherwise).
        """
        try:
            last_instruction = self._execution_stack.get()
            # 0F, 10 and 11 are return instructions (e.g., return v5).
            if 0x0F <= last_instruction[0] <= 0x11:
                return self._register_values[last_instruction[1][0][1]]
            else:
                return None
        except IndexError:
            return None

    def get_all_possible_return_values(self):
        """
        If the last instruction in the stack is a return instruction, get the return
        value (if available).

        :return: The return value (if available, None otherwise).
        """
        return_values = []
        try:
            for ins_pair in self._execution_stack.getAll():
                # 0F, 10 and 11 are return instructions (e.g., return v5).
                if 0x0F <= ins_pair[0] <= 0x11:
                    return_values.append(ins_pair[1][0][1])
        except IndexError:
            return return_values
        return return_values

    def get_last_instruction_values(self):
        """
        Get an ordered list with the values of the registers used in the last
        instruction.

        :return: A list with the values of the registers used in the last instruction.
        """
        if not self._register_values or not self._execution_stack:
            return []

        try:
            last_instruction_operands = self._execution_stack.get()[1]
            return [
                self._register_values.get(operand[1], None)
                for operand in last_instruction_operands
                if operand[0] == Operand.REGISTER
            ]
        except IndexError:
            return []


class TaintAnalysis(ABC):
    def __init__(
        self,
        target_method: Union[MethodAnalysis, Iterable[MethodAnalysis]],
        analysis_info: AndroidAnalysis,
        path_max_length: int = 5,
    ):
        self.logger = logging.getLogger(self.__class__.__name__)

        self._target_method = target_method
        self._analysis_info = analysis_info
        self._max_depth = path_max_length

        # The list of methods that contain the vulnerability. The key is the full method
        # signature where the vulnerable code was found, while the value is a tuple with
        # the signature of the vulnerable target method/API/other info about the
        # vulnerability and the full path leading to the vulnerability.
        self.vulnerabilities = {}

    def _recursive_check_path(
        self,
        path: List[MethodAnalysis],
        path_start_index: int = 0,
        last_invocation_params: list = None,
    ):
        # At least 2 methods are needed for a vulnerability: the callee (vulnerable
        # target method) and the caller method. Since this method is called recursively,
        # if the path to check doesn't contain at least 2 methods, return immediately:
        # the vulnerable target method (most likely an Android API) is the last item in
        # the path and we want to also check where this target method is called, so
        # having a caller method is mandatory.
        if path_start_index > len(path) - 2:
            return

        caller = path[path_start_index]
        target = path[path_start_index + 1]

        # Do not follow any path containing methods that should to be ignored.
        if self._analysis_info.ignore_libs:
            if any(
                caller.get_class_name().startswith(prefix)
                for prefix in self._analysis_info.ignored_classes_prefixes
            ):
                return

        register_analyzer = RegisterAnalyzer(
            self._analysis_info.get_apk_analysis(),
            self._analysis_info.get_dex_analysis(),
        )

        self.logger.debug("")
        self.logger.debug(
            f"Analyzing code in method {caller.class_name}->"
            f"{caller.name}{caller.descriptor}"
        )

        # If the previous method in path passed some parameters to the current method
        # (caller), then use those values to initialize the corresponding registers of
        # the current method (caller). This way we can track constant values passed from
        # caller methods to target methods.
        param_registers = caller.get_method().get_information().get("params")
        if last_invocation_params and param_registers:
            self.logger.debug("Last invocation passed some parameters to this method:")
            # Loop in reverse order to fill the parameters starting from the last one.
            for param, val in reversed(
                list(zip(reversed(param_registers), reversed(last_invocation_params)))
            ):
                self.logger.debug(f"  v{param[0]} = {val}")
                register_analyzer.initialize_register_value(param[0], val)

        offset = 0
        next_invocation_found = False
        for ins in caller.get_method().get_instructions():
            self.logger.debug(
                f"(0x{offset:04x}) {ins.get_name():20} {ins.get_output()}"
            )

            if ins.get_output().endswith(
                f"{target.class_name}->{target.name}{target.descriptor}"
            ):
                next_invocation_found = True

                # The current instruction is an invocation to the next method in path.
                if path[-1] == target:
                    self.logger.debug(
                        "This is the target method invocation: "
                        f"{ins.get_name()} {ins.get_output()}"
                    )
                else:
                    self.logger.debug(
                        "This is the next method invocation to follow: "
                        f"{ins.get_name()} {ins.get_output()}"
                    )

                register_analyzer.load_instructions(
                    caller.get_method().get_instructions(), offset
                )
                last_invocation_params = register_analyzer.get_last_instruction_values()

                self.logger.debug(
                    f"Register values for last instruction: {last_invocation_params}"
                )

                # An invocation to the next method in path was found, so continue
                # analyzing the next method.
                self._recursive_check_path(
                    path,
                    path_start_index + 1,
                    last_invocation_params,
                )

                # The last method in path is the target method, so if the current target
                # method is the last one, it means we are checking the invocation of the
                # actual (potentially vulnerable) target method.
                if path[-1] == target:
                    self.vulnerable_path_found_callback(
                        path, caller, target, last_invocation_params
                    )

                self.logger.debug("")
                self.logger.debug(
                    "...continue analyzing code in method "
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                )

            offset += ins.get_length()

        if not next_invocation_found:
            # The next method it's not called directly from code. This method could be
            # inside an inner/anonymous class (e.g., onClick listener).
            # The current instruction is an invocation to the next method in path.
            self.logger.debug(
                "This is the next method to follow: "
                f"{target.class_name}->{target.name}{target.descriptor}"
            )

            # Continue analyzing the next method.
            self._recursive_check_path(path, path_start_index + 1, [])

            # The last method in path is the target method, so if the current target
            # method is the last one, it means we are checking the invocation of the
            # actual (potentially vulnerable) target method.
            if path[-1] == target:
                self.vulnerable_path_found_callback(
                    path, caller, target, last_invocation_params
                )

    def get_paths_to_target_method(self) -> List[List[MethodAnalysis]]:
        """
        Get a list with all the (longest) paths leading to a target method.

        :return: A list of paths (each path is a list of methods, where the target
                 method is the last item in each path).
        """

        def recursive_graph(graph: nx.MultiDiGraph(), method: MethodAnalysis):
            # If not already present, add the current method as a node to the graph,
            # otherwise return, since this node was already processed.
            if method not in graph.nodes:
                graph.add_node(method)
            else:
                return

            # Add to the graph all the callers of the current method and repeat the same
            # operation for each caller.
            num_callers = 0
            for _, caller, _ in method.get_xref_from():
                num_callers += 1
                recursive_graph(graph, caller)
                graph.add_edge(caller, method)

            if not num_callers:
                # The current method has no xref, so it's not called directly from code.
                # However, the class containing this method could be an inner/anonymous
                # class used to define a method that is not called directly (e.g.,
                # onClick listener).
                class_analysis = (
                    self._analysis_info.get_dex_analysis().get_class_analysis(
                        method.get_class_name()
                    )
                )
                # The class containing the method was not found.
                if not class_analysis:
                    return
                for caller in class_analysis.get_xref_from():
                    for meth in caller.get_methods():
                        e_meth = meth.get_method()
                        if isinstance(e_meth, EncodedMethod):
                            for i in e_meth.get_instructions():
                                if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
                                    if i.get_string() == method.get_class_name():
                                        if meth not in graph.nodes:
                                            graph.add_node(meth)
                                            graph.add_edge(meth, method)
                                            break

        def get_paths(method: MethodAnalysis) -> List[List[MethodAnalysis]]:
            if not method:
                # There are no paths if the target method is not set.
                return []

            graph = nx.MultiDiGraph()
            recursive_graph(graph, method)

            # Find all paths that have method destination. The smallest path is made by
            # the destination method only.
            paths_dict = {str(method): [method]}
            for node in graph.nodes:
                for new_path in nx.all_simple_paths(graph, node, method):
                    # If a positive maximum path length was provided, crop the path to
                    # the maximum path length, otherwise add the complete path.
                    if self._max_depth > 0:
                        path_to_add = new_path[-self._max_depth :]
                    else:
                        path_to_add = new_path
                    paths_dict[str(path_to_add)[1:-1]] = path_to_add

            # Keep only the longest paths (remove all the sub-paths that are part of
            # longer paths).
            longest_paths_dict = {}
            for path in sorted(paths_dict, key=len, reverse=True):
                if not any(key.endswith(path) for key in longest_paths_dict):
                    longest_paths_dict[path] = paths_dict[path]

            return list(longest_paths_dict.values())

        if not self._target_method:
            return []

        elif isinstance(self._target_method, Iterable):
            # We have to check a list of target methods, so find the paths for each
            # target method.
            to_return = []
            for m in self._target_method:
                if isinstance(m, MethodAnalysis):
                    to_return.extend(get_paths(m))
                elif m:
                    raise ValueError(
                        "The target method must be a MethodAnalysis or an iterable "
                        f"of MethodAnalysis (iterable of {type(m)} is not supported)"
                    )
            return to_return

        elif isinstance(self._target_method, MethodAnalysis):
            return get_paths(self._target_method)

        else:
            raise ValueError(
                "The target method must be a MethodAnalysis or an iterable "
                f"of MethodAnalysis ({type(self._target_method)} is not supported)"
            )

    def find_code_vulnerabilities(self) -> List[VulnerableCode]:
        # Find all the code paths leading to the target method(s).
        paths_to_check = self.get_paths_to_target_method()

        # Check every path leading to a target method invocation.
        for path in paths_to_check:
            self._recursive_check_path(path, last_invocation_params=[])

        code_vulnerabilities = [
            VulnerableCode(value[0], key, value[1])
            for key, value in self.vulnerabilities.items()
        ]

        return code_vulnerabilities

    @abstractmethod
    def vulnerable_path_found_callback(
        self,
        full_path: List[MethodAnalysis],
        caller: MethodAnalysis = None,
        target: MethodAnalysis = None,
        last_invocation_params: list = None,
    ):
        # This method is called when a path to the potentially vulnerable target
        # method(s) is found. It has to be implemented for each different vulnerability,
        # since the implementation depends on the vulnerability. See the already
        # implemented vulnerability checks for more details.
        raise NotImplementedError(
            "This custom method must be implemented for each vulnerability"
        )
