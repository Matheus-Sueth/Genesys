from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Optional

# from itertools import chain
from collections import OrderedDict


@dataclass
class State:
    name: str
    refId: str
    variables: Optional[dict] = None
    actions: Optional[list] = None


@dataclass
class Task:
    name: str
    refId: str
    variables: Optional[dict] = None
    actions: Optional[list] = None
    outputPaths: Optional[dict] = None


@dataclass
class InboundCall:
    name: str
    division: str
    startUpRef: str
    initialGreeting: dict
    defaultLanguage: str
    supportedLanguages: dict
    settingsActionDefaults: dict
    settingsErrorHandling: dict
    settingsMenu: dict
    settingsPrompts: dict
    settingsSpeechRec: dict
    description: Optional[str] = field(default="")
    variables: Optional[dict] = None
    tasks: Optional[list[Task]] = None
    menus: Optional[list] = None

    def __repr__(self) -> str:
        dados = f"Name: {self.name}, Description: {self.description}"
        return f"InboundCall({dados})"

    def __str__(self) -> str:
        qtd_tasks = len(self.tasks) if self.tasks is not None else 0
        qtd_menus = len(self.menus) if self.menus is not None else 0
        dados = (
            f"\nName: {self.name}\nDescription: {self.description}"
            f"\nTasks: {qtd_tasks}\nMenus: {qtd_menus}"
        )
        return f"InboundCall({dados})"

    def search_flow(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "callCommonModule":
                        name_flow = list(valor["commonModule"].keys())[0]
                        lista.append((name_flow, "commonModule"))
                        continue
                    case "transferToFlow":
                        name_flow = valor["targetFlow"]["name"]
                        lista.append((name_flow, "inboundcall"))
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")

    def search_data_action(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        category = list(valor["category"].keys())[0]
                        name_data_action = list(
                            valor["category"][category]["dataAction"].keys()
                        )[0]
                        lista.append((category, name_data_action))
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")

    def search_attribute(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "getParticipantData":
                        for atribute in valor["attributes"]:
                            name = atribute["attribute"]["name"]
                            name_attribute = name["lit"] if name.get("lit", False) else name["exp"]
                            lista.append(((name_attribute,'getParticipantData'), "inboundcall"))
                    case "setParticipantData":
                        for atribute in valor["attributes"]:
                            name = atribute["attribute"]["name"]
                            name_attribute = name["lit"] if name.get("lit", False) else name["exp"]
                            lista.append(((name_attribute,'setParticipantData'), "inboundcall"))
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")

    def get_dependencies(self, type_action: str) -> list:
        dados = []
        for task in self.tasks:
            for action in task.actions:
                match type_action:
                    case "flows":
                        result = self.search_flow(action, list())
                    case "data_actions":
                        result = self.search_data_action(action, list())
                    case "attributes":
                        result = self.search_attribute(action, list())
                    case _:
                        pass
                dados.extend(result)
        return sorted(list(set(dados)))

    def class_asdict(self) -> dict:
        data = {"inboundCall": OrderedDict({})}
        for chave, valor in asdict(self).items():
            if valor is not None:
                data["inboundCall"][chave] = valor
        # tasks = [{'task':asdict(task)} for task in self.tasks]
        tasks = []
        for task in self.tasks:
            aux_task = {"task": OrderedDict({})}
            for chave, valor in asdict(task).items():
                if valor is not None:
                    aux_task["task"][chave] = valor
            if aux_task:
                tasks.append(aux_task)

        if task:
            data["inboundCall"]["tasks"] = tasks
        else:
            if data["inboundCall"].get("tasks"):
                del data["inboundCall"]["tasks"]
        return data


@dataclass
class InboundShortMessage:
    name: str
    division: str
    startUpRef: str
    defaultLanguage: str
    supportedLanguages: dict
    settingsErrorHandling: dict
    description: Optional[str] = field(default="")
    variables: Optional[dict] = None
    tasks: Optional[list[Task]] = None
    states: Optional[list[State]] = None

    def __repr__(self) -> str:
        dados = f"Name: {self.name}, Description: {self.description}"
        return f"InboundShortMessage({dados})"

    def __str__(self) -> str:
        qtd_tasks = len(self.tasks) if self.tasks is not None else 0
        qtd_states = len(self.states) if self.states is not None else 0
        dados = (
            f"\nName: {self.name}\nDescription: {self.description}"
            f"\nTasks: {qtd_tasks}\nStates: {qtd_states}"
        )
        return f"InboundShortMessage({dados})"

    def search_flow(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "callBotFlow":
                        name_flow = list(valor["botFlow"].keys())[0]
                        lista.append((name_flow, "bot"))
                        continue
                    case "callCommonModule":
                        name_flow = list(valor["commonModule"].keys())[0]
                        lista.append((name_flow, "commonModule"))
                        continue
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")

    def search_data_action(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        category = list(valor["category"].keys())[0]
                        name_data_action = list(
                            valor["category"][category]["dataAction"].keys()
                        )[0]
                        lista.append((category, name_data_action))
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")

    def search_attribute(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case "getParticipantData":
                        for atribute in valor["attributes"]:
                            name = atribute["attribute"]["name"]
                            name_attribute = name["lit"] if name.get("lit", False) else name["exp"]
                            lista.append(((name_attribute,'getParticipantData'), "inboundcall"))
                    case "setParticipantData":
                        for atribute in valor["attributes"]:
                            name = atribute["attribute"]["name"]
                            name_attribute = name["lit"] if name.get("lit", False) else name["exp"]
                            lista.append(((name_attribute,'setParticipantData'), "inboundcall"))
                    case "decision":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "switch":
                        evaluate_aux = valor["evaluate"]
                        if evaluate_aux.get("firstTrue"):
                            evaluate = evaluate_aux["firstTrue"]
                        else:
                            evaluate = evaluate_aux["firstMatch"]["string"]
                        for case in evaluate["cases"]:
                            if case["case"].get("actions"):
                                for action in case["case"]["actions"]:
                                    self.search_flow(action, lista)
                        else:
                            if evaluate.get("default"):
                                default = evaluate["default"]
                                if default.get("actions"):
                                    for action in default["actions"]:
                                        self.search_flow(action, lista)
                    case "collectInput":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "callData":
                        if valor.get("outputs"):
                            for saidas in valor["outputs"].values():
                                if saidas.get("actions"):
                                    for action in saidas["actions"]:
                                        self.search_flow(action, lista)
                    case "loop":
                        if valor.get("outputs"):
                            if valor["outputs"]["loop"].get("actions"):
                                actions = valor["outputs"]["loop"]["actions"]
                                for action in actions:
                                    self.search_flow(action, lista)
                    case _:
                        continue
            return lista
        except Exception as erro:
            raise Exception(f"Ocorreu um erro: {erro}\nAction: {action}")
        
    def get_dependencies(self, type_action: str) -> list:
        dados = []
        for task in self.tasks:
            for action in task.actions:
                match type_action:
                    case "flows":
                        result = self.search_flow(action, list())
                    case "data_actions":
                        result = self.search_data_action(action, list())
                    case "attributes":
                        result = self.search_attribute(action, list())
                    case _:
                        pass
                dados.extend(result)

        for state in self.states:
            for action in state.actions:
                match type_action:
                    case "flows":
                        result = self.search_flow(action, list())
                    case "data_actions":
                        result = self.search_data_action(action, list())
                    case "attributes":
                        result = self.search_attribute(action, list())
                    case _:
                        pass
                dados.extend(result)
        return sorted(list(set(dados)))

    def class_asdict(self) -> dict:
        data = {"inboundShortMessage": OrderedDict({})}
        for chave, valor in asdict(self).items():
            if valor is not None:
                data["inboundShortMessage"][chave] = valor
        # tasks = [{'task':asdict(task)} for task in self.tasks]
        tasks = []
        for task in self.tasks:
            aux_task = {"task": OrderedDict({})}
            for chave, valor in asdict(task).items():
                if valor is not None:
                    aux_task["task"][chave] = valor
            if aux_task:
                tasks.append(aux_task)

        if task:
            data["inboundShortMessage"]["tasks"] = tasks
        else:
            if data["inboundShortMessage"].get("tasks"):
                del data["inboundShortMessage"]["tasks"]
        return data
