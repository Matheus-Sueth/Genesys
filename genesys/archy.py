from __future__ import annotations
import os
import re
import json
import yaml
from genesys.api import Genesys
import importlib.resources as imp_res
import subprocess
import genesys.type_flows.flows as tf_flow
from collections import OrderedDict


def represent_ordereddict(dumper, data):
    return dumper.represent_dict(data.items())


yaml.add_representer(OrderedDict, represent_ordereddict)


class FileYaml:
    PREFIXE = ["B", "KB", "MB", "GB", "TB"]
    TYPE_FLOWS = [
        "inboundcall",
        "inboundshortmessage",
        "inboundemail",
        "inboundchat",
        "outboundcall",
        "bot",
        "digitalbot",
        "commonmodule",
        "inqueuecall",
        "inqueueemail",
        "inqueueshortmessage",
        "securecall",
        "voicemail",
        "workflow",
    ]

    def __init__(self, path_file: str) -> None:
        self.path_file = path_file
        assert os.path.exists(self.path_file)
        with open(self.path_file, "rb") as arq_file:
            file = arq_file.read().decode("utf-8")
        self.file_genesys_txt = file.replace("\t", "")
        self.json_file = OrderedDict(json.loads(self.yaml_to_json()))
        self.auxiliar = OrderedDict(json.loads(self.yaml_to_json()))
        self.definir_flow()

    def __repr__(self) -> str:
        return f"FileYaml(Path: {self.path_file})"

    def __str__(self) -> str:
        path = self.path_file
        nome = os.path.basename(self.path_file)
        is_flow = self.flow is None
        size, prefixe = self._return_size(os.path.getsize(path))
        return (
            f"FileYaml\nPath: {path}\nName: {nome}\n"
            f"Flow is None: {is_flow}\nSize: {size:.2f} {prefixe}"
        )

    def _return_size(self, number: float, prefixe: int = 0) -> tuple[int, str]:
        if number < 1000:
            return number, self.PREFIXE[prefixe]
        prefixe += 1
        return self._return_size(number / 1024, prefixe)

    def definir_flow(self):
        self.flow_type = list(self.json_file.keys())[0]
        if self.flow_type == "inboundCall":
            tasks = [
                tf_flow.Task(**task["task"])
                for task in self.json_file[self.flow_type]["tasks"]
            ]
            del self.auxiliar[self.flow_type]["tasks"]
            self.flow = tf_flow.InboundCall(
                **self.auxiliar[self.flow_type], tasks=tasks
            )
        elif self.flow_type == "inboundShortMessage":
            states, tasks = [], []

            if self.json_file[self.flow_type].get("states", False):
                states = [
                    tf_flow.Task(**state["state"])
                    for state in self.json_file[self.flow_type]["states"]
                ]
                del self.auxiliar[self.flow_type]["states"]

            if self.json_file[self.flow_type].get("tasks", False):
                tasks = [
                    tf_flow.Task(**task["task"])
                    for task in self.json_file[self.flow_type]["tasks"]
                ]
                del self.auxiliar[self.flow_type]["tasks"]

            self.flow = tf_flow.InboundShortMessage(
                **self.auxiliar[self.flow_type], states=states, tasks=tasks
            )
        else:
            self.flow = None

    def trocar_dados(self, variavel_antiga: str, varivel_nova: str) -> None:
        self.file_genesys_txt = self.file_genesys_txt.replace(
            variavel_antiga, varivel_nova
        )
        self.json_file = json.loads(self.yaml_to_json())
        self.auxiliar = json.loads(self.yaml_to_json())
        self.definir_flow()

    def yaml_to_json(self) -> str:
        data = yaml.safe_load(self.file_genesys_txt)
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save_yaml_to_file(self) -> FileYaml:
        with open(self.path_file, "w", encoding="utf-8") as yaml_file:
            yaml.dump(
                self.flow.class_asdict(),
                yaml_file,
                default_flow_style=False,
                allow_unicode=True,
            )
        return FileYaml(self.path_file)


class Archy:
    padrao = re.compile(r"_v\d+-\d+\.yaml$")
    DADOS = Genesys.DADOS

    def __init__(self, org: str) -> None:
        if org not in self.DADOS.keys():
            raise ValueError("Organização Desconhecida")
        self.LOCATION = self.DADOS[org]["URL_AUTH"]
        self.CLIENT_ID = self.DADOS[org]["CLIENT_ID"]
        self.CLIENT_SECRET = self.DADOS[org]["CLIENT_SECRET"]
        self.api = Genesys(org)

    def __new__(self, *args):
        if not hasattr(self, "instance"):
            self.instance = super(Archy, self).__new__(self)
        return self.instance

    def get_file_flow(flow_name: str, flow_version: str, output_dir: str):
        arquivos = os.listdir(os.path.abspath(f"{output_dir}/"))
        if flow_version == "latest":
            arquivos = os.listdir(os.path.abspath(f"{output_dir}/"))

            flow_files = [
                arquivo
                for arquivo in arquivos
                if arquivo.startswith(
                    flow_name,
                )
            ].sort()
        else:
            flow_files = [
                arquivo
                for arquivo in arquivos
                if flow_name in arquivo and flow_version in arquivo
            ]
        if len(flow_files) == 0:
            raise ValueError("No flow filess")
        else:
            caminho_file = os.path.join(
                output_dir,
                flow_files[-1],
            )
        return caminho_file

    def export_flow_subprocess(
        self,
        flow_name: str,
        flow_type: str = "inboundcall",
        flow_version: str = "latest",
        output_dir: str = "flows",
    ):
        aux_powershell = r"\v1.0\powershell.exe"
        powershell = rf"C:\Windows\System32\WindowsPowerShell{aux_powershell}"
        cmd = (
            f'archy export --flowName "{flow_name}" --flowType {flow_type} '
            f'--flowVersion {flow_version} --outputDir "{output_dir}" '
            "--exportType yaml --authTokenIsClientCredentials true "
            f"--clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET}"
            f" --location {self.LOCATION}"
        )
        try:
            file_flow, result_error = None, None
            results, error = subprocess.Popen(
                [
                    powershell,
                    "-Command",
                    cmd,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            ).communicate()
            if results:
                dados = results.decode()
                lista_dados = [
                    dado.split(":")
                    for dado in dados.split("\n")
                    if dado.strip() != "" and ":" in dado
                ]
                dict_dados = {}
                for dado in lista_dados:
                    chave = dado[0].strip()
                    valor = ":".join(dado[1:]).strip()
                    dict_dados[chave] = valor.replace("'", "")
                assert dict_dados["exit code"] == "0"
                file_flow = FileYaml(dict_dados["Export file"])
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = erro
        finally:
            return (dict_dados, result_error, file_flow)

    def publish_flow_subprocess(self, flow_file):
        aux_powershell = r"\v1.0\powershell.exe"
        powershell = rf"C:\Windows\System32\WindowsPowerShell{aux_powershell}"
        try:
            dict_dados, result_error = None, None
            file_flow = FileYaml(flow_file)
            flow_name = file_flow.flow.name
            if self.api.search_flow_is_prd(flow_name):
                erro = f"Fluxo: {flow_name} é utilizado nos ivrs de produção"
                raise Exception(erro)
            flows = file_flow.flow.get_dependencies("flows")
            dependencies = [
                self.publish_flow_empty_subprocess(flow_name_dependencie)
                for flow_name_dependencie, flow_type_dependencie in flows
                if self.api.get_flows(
                    flow_name_or_description=flow_name_dependencie,
                    type_flow=flow_type_dependencie,
                ).total
                == 0
            ]
            cmd = (
                f'archy publish --file "{flow_file}"'
                f" --clientId {self.CLIENT_ID}"
                f" --clientSecret {self.CLIENT_SECRET}"
                f" --location {self.LOCATION}"
            )
            results, error = subprocess.Popen(
                [
                    powershell,
                    "-Command",
                    cmd,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            ).communicate()
            if results:
                dados = results.decode()
                lista_dados = [
                    dado.split(":")
                    for dado in dados.split("\n")
                    if dado.strip() != "" and ":" in dado
                ]
                dict_dados = {}
                dict_dados["dependencies"] = dependencies
                for dado in lista_dados:
                    chave = dado[0].strip()
                    valor = ":".join(dado[1:]).strip()
                    dict_dados[chave] = valor
                assert dict_dados["exit code"] == "0"
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = erro
        finally:
            return (dict_dados, result_error)

    def publish_flow_empty_subprocess(
        self, flow_name, description="Fluxo_Vazio"
    ) -> tuple[dict | None, str | None]:
        aux_powershell = r"\v1.0\powershell.exe"
        powershell = rf"C:\Windows\System32\WindowsPowerShell{aux_powershell}"
        try:
            dict_dados, result_error = None, None
            flow_file_name = imp_res.files(
                "genesys",
                "inbound_call_start.yaml",
            )
            file_flow = FileYaml(flow_file_name)
            if self.api.search_flow_is_prd(flow_name):
                erro = f"Fluxo: {flow_name} é utilizado nos ivrs de produção"
                raise Exception(erro)
            file_flow.flow.name = flow_name
            file_flow.flow.description = description
            file_flow.save_yaml_to_file()
            cmd = (
                f'archy publish --file "{flow_file_name}"'
                f" --clientId {self.CLIENT_ID}"
                f" --clientSecret {self.CLIENT_SECRET}"
                f"  --location {self.LOCATION}"
            )
            results, error = subprocess.Popen(
                [
                    powershell,
                    "-Command",
                    cmd,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            ).communicate()
            if results:
                dados = results.decode()
                lista_dados = [
                    dado.split(":")
                    for dado in dados.split("\n")
                    if dado.strip() != "" and ":" in dado
                ]
                dict_dados = {}
                for dado in lista_dados:
                    chave = dado[0].strip()
                    valor = ":".join(dado[1:]).strip()
                    dict_dados[chave] = valor
                assert dict_dados["exit code"] == "0"
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = erro
        finally:
            return (dict_dados, result_error)
