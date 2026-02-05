from __future__ import annotations
import os
import re
import json
import yaml
import importlib.resources as imp_res
from importlib.abc import Traversable
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from genesys.api import Genesys
import genesys.flows as tf_flow


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

    def __init__(self, path_file: Traversable | str) -> None:
        self.path_file = path_file  # opcional: para debug/log

        # 1) Carrega conteúdo (texto) a partir do tipo recebido
        if isinstance(path_file, str):
            path = path_file
            if not os.path.exists(path):
                raise FileNotFoundError(f"Arquivo não encontrado: {path}")
            with open(path, "rb") as arq_file:
                file_txt = arq_file.read().decode("utf-8")
        else:
            # Traversable (ex.: importlib.resources.files(...).joinpath(...))
            # read_text é o caminho mais simples; fallback para open('rb') se necessário
            try:
                file_txt = path_file.read_text(encoding="utf-8")
            except AttributeError:
                with path_file.open("rb") as f:
                    file_txt = f.read().decode("utf-8")

        self.file_genesys_txt = file_txt.replace("\t", "")
        self.json_file = OrderedDict(json.loads(self.yaml_to_json()))
        self.auxiliar = OrderedDict(json.loads(self.yaml_to_json()))
        self.definir_flow()

    def __repr__(self) -> str:
        return f"FileYaml(Path: {self.path_file})"

    def __str__(self) -> str:
        path = self.path_file

        if isinstance(path, str):
            nome = os.path.basename(path)
            size_bytes = os.path.getsize(path)
            path_display = path
        else:
            # Traversable: não é path real; mostre algo útil
            nome = getattr(path, "name", "<resource>")
            try:
                size_bytes = len(path.read_bytes())
            except Exception:
                # fallback: tenta abrir em binário e medir
                with path.open("rb") as f:
                    size_bytes = len(f.read())
            path_display = f"<resource:{nome}>"

        is_flow = self.flow is None
        size, prefixe = self._return_size(size_bytes)

        return (
            f"FileYaml\nPath: {path_display}\nName: {nome}\n"
            f"Flow is None: {is_flow}\nSize: {size:.2f} {prefixe}"
        )

    def _return_size(self, number: float, prefixe: int = 0) -> tuple[float, str]:
        if number < 1000:
            return number, self.PREFIXE[prefixe]
        prefixe += 1
        return self._return_size(number / 1024, prefixe)

    def definir_flow(self):
        states, tasks = [], []
        self.flow_type = list(self.json_file.keys())[0]
        if self.flow_type == "inboundCall":
            if self.json_file[self.flow_type].get("tasks", False):
                tasks = [
                    tf_flow.Task(**task["task"])
                    for task in self.json_file[self.flow_type]["tasks"]
                ]
                del self.auxiliar[self.flow_type]["tasks"]
            self.flow = tf_flow.InboundCall(
                **self.auxiliar[self.flow_type], tasks=tasks
            )
        elif self.flow_type == "inboundShortMessage":
            if self.json_file[self.flow_type].get("states", False):
                states = [
                    tf_flow.State(**state["state"])
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

    def save_yaml_to_file(self, output_path: str | None = None) -> "FileYaml":
        if self.flow is None:
            raise Exception("Nao existe variavel self.flow")

        # Caso 1: já é um path real
        if isinstance(self.path_file, str):
            target = self.path_file
        else:
            # Caso 2: é recurso empacotado: precisa de destino
            if not output_path:
                raise ValueError(
                    "self.path_file é um recurso (Traversable) e não pode ser sobrescrito. "
                    "Informe output_path para salvar em um arquivo real."
                )
            target = output_path

        with open(target, "w", encoding="utf-8") as yaml_file:
            yaml.dump(
                self.flow.class_asdict(),
                yaml_file,
                default_flow_style=False,
                allow_unicode=True,
            )

        return FileYaml(target)


@dataclass
class ArchyExportResult:
    ok: bool
    exit_code: int
    job_id: str
    export_file_host: Optional[str]
    stdout: str
    stderr: str


class Archy:
    padrao = re.compile(r"_v\d+-\d+\.yaml$")

    def __init__(
        self,
        genesys: Genesys,
        compose_file: str = "docker-compose.yml",
        compose_service: str = "app-genesys",
        volume_hint: str = "archy_out",
        host_exports_dir: str = "flows",
    ) -> None:
        self.api = genesys
        self.location = genesys.region.suffix
        self.compose_file = compose_file
        self.compose_service = compose_service
        self.volume_hint = volume_hint
        self.host_exports_dir = host_exports_dir

    def __str__(self) -> str:
        return f"Archy({self.api})"

    @staticmethod
    def get_file_flow(flow_name: str, flow_version: str, output_dir: str):
        arquivos = os.listdir(os.path.abspath(f"{output_dir}/"))
        if flow_version == "latest":
            arquivos = os.listdir(os.path.abspath(f"{output_dir}/"))

            flow_files = sorted([arquivo for arquivo in arquivos if arquivo.startswith(flow_name)])
        else:
            flow_files = [
                arquivo
                for arquivo in arquivos
                if flow_name in arquivo and flow_version in arquivo
            ]
        if flow_files is None or len(flow_files) == 0:
            raise ValueError("No flow files")
        else:
            caminho_file = os.path.join(
                output_dir,
                flow_files[-1],
            )
        return caminho_file

    def _run(self, cmd: list[str], cwd: Optional[str] = None) -> tuple[int, str, str]:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # ou "ignore"
        )
        return p.returncode, (p.stdout or ""), (p.stderr or "")

    def _detect_volume_name(self) -> str:
        """
        Descobre o nome real do volume do compose no Docker.
        Em geral vira algo tipo: <projeto>_archy_out
        """
        code, out, err = self._run(["docker", "volume", "ls", "--format", "{{.Name}}"])
        if code != 0:
            raise RuntimeError(f"Falha ao listar volumes: {err.strip()}")

        names = [line.strip() for line in out.splitlines() if line.strip()]
        # tenta match exato
        if self.volume_hint in names:
            return self.volume_hint

        # tenta encontrar volumes que terminem com _archy_out (prefixo do projeto)
        suffix = f"_{self.volume_hint}"
        for n in names:
            if n.endswith(suffix):
                return n

        raise RuntimeError(
            f"Não encontrei o volume '{self.volume_hint}' (nem '*_{self.volume_hint}'). "
            f"Verifique o docker-compose.yml e o 'docker volume ls'."
        )

    def _copy_from_volume_to_host(self, job_id: str, dest_dir: Path) -> None:
        """
        Copia tudo de /work/exports/<job_id> (volume) para dest_dir (host).
        """
        volume = self._detect_volume_name()
        dest_dir.mkdir(parents=True, exist_ok=True)

        # No Windows, o Docker CLI aceita caminho absoluto do Windows no -v.
        host_path = str(dest_dir.resolve())

        copy_cmd = [
            "docker", "run", "--rm",
            "-v", f"{volume}:/data",
            "-v", f"{host_path}:/host",
            "busybox", "sh", "-lc",
            f"cp -rf /data/exports/{job_id}/* /host/ && ls -la /host"
        ]

        code, out, err = self._run(copy_cmd)
        if code != 0:
            raise RuntimeError(
                "Falha ao copiar do volume para o host.\n"
                f"CMD: {' '.join(copy_cmd)}\n"
                f"STDOUT: {out}\nSTDERR: {err}"
            )
        
    def export_flow(
        self,
        *,
        flow_name: str,
        flow_type: str,
        flow_version: str = "latest",
        export_type: str = "yaml",
        project_dir: Optional[str] = None,
    ) -> tuple[ArchyExportResult, Optional[FileYaml]]:
        """
        Exporta um fluxo pelo Archy dentro do container e traz o arquivo para o host.

        Retorna:
          - ArchyExportResult (com path host)
          - FileYaml (se ok)
        """
        job_id = self.api.information_token['organization']['id']

        # Onde o Archy vai escrever dentro do container (volume /work)
        output_dir_container = f"/work/exports/{job_id}"

        # Onde o arquivo vai cair no host
        base = Path(project_dir) if project_dir else Path.cwd()
        export_dir_host = base / self.host_exports_dir / job_id
        token_info = self.api.token_provider.token_info()

        cmd = [
            "docker", "compose",
            "-f", self.compose_file,
            "run", "--rm", "-T",
            "--entrypoint", "archy",
            self.compose_service,
            "export",
            "--flowName", flow_name,
            "--flowType", flow_type,
            "--flowVersion", flow_version,
            "--exportType", export_type,
            "--outputDir", output_dir_container,
            "--authToken", self.api.token_provider.get_access_token(),
            "--authTokenIsClientCredentials", "true" if token_info["type"] == "ClientCredentials" else "false",
            "--location", self.api.region.suffix,
        ]

        code, out, err = self._run(cmd, cwd=str(base))

        # Mesmo quando o archy falha, a gente devolve o payload pra debug
        if code != 0:
            result = ArchyExportResult(
                ok=False,
                exit_code=code,
                job_id=job_id,
                export_file_host=None,
                stdout=out,
                stderr=err,
            )
            return result, None

        # Copia do volume -> host
        self._copy_from_volume_to_host(job_id=job_id, dest_dir=export_dir_host)

        # Descobre qual YAML veio (padrão do archy: <flow>_vX-Y.yaml)
        yaml_files = sorted(export_dir_host.glob("*.yaml"))
        export_file_host = str(yaml_files[0].resolve()) if yaml_files else None

        ok = export_file_host is not None

        result = ArchyExportResult(
            ok=ok,
            exit_code=0,
            job_id=job_id,
            export_file_host=export_file_host,
            stdout=out,
            stderr=err,
        )

        if not ok:
            return result, None

        file_flow = FileYaml(export_file_host)
        return result, file_flow

    def publish_flow_subprocess(self, flow_file):
        dict_dados, result_error = None, None
        try:
            file_flow = FileYaml(flow_file)
            if file_flow.flow is None:
                raise Exception("Nao existe variavel file_flow.flow")
            flow_name = file_flow.flow.name
            if self.api.search_flow_is_prd(flow_name):
                raise Exception(
                    f"Fluxo: {flow_name} é utilizado nos IVRs de produção"
                )
            flows = file_flow.flow.get_dependencies("flows")
            dependencies: list = []
            for flow_name_dependencie, flow_type_dependencie in flows:
                if (
                    self.api.get_flows(
                        flow_name_or_description=flow_name_dependencie,
                        type_flow=flow_type_dependencie,
                    )["total"]
                    == 0
                ):
                    dependencies.append(
                        self.publish_flow_empty_subprocess(flow_name_dependencie)
                    )
            # Build the publish command as a list of arguments
            cmd = [
                "archy",
                "publish",
                "--file",
                flow_file,
                "--authToken",
                self.api.token_provider.get_access_token(),
                "--location",
                self.location,
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            results, error = process.communicate()
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
                if dict_dados.get("exit code") != "0":
                    raise Exception(
                        f"Erro ao publicar o fluxo: {dict_dados.get('exit code')}"
                    )
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = str(erro)
        finally:
            return (dict_dados, result_error)

    def publish_flow_empty_subprocess(
        self, flow_name, description="Fluxo_Vazio"
    ) -> tuple[dict | None, str | None]:
        dict_dados, result_error = None, None
        try:
            flow_file_name = imp_res.files("genesys").joinpath("inbound_call_start.yaml")
            file_flow = FileYaml(flow_file_name)
            if file_flow.flow is None:
                raise Exception("Nao existe variavel file_flow.flow")
            if self.api.search_flow_is_prd(flow_name):
                raise Exception(
                    f"Fluxo: {flow_name} é utilizado nos IVRs de produção"
                )
            file_flow.flow.name = flow_name
            file_flow.flow.description = description
            file_flow.save_yaml_to_file()
            # Build command to publish the empty flow using archy
            cmd = [
                "archy",
                "publish",
                "--file",
                str(flow_file_name),
                "--authToken",
                self.api.token_provider.get_access_token(),
                "--location",
                self.location,
            ]
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            results, error = process.communicate()
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
                if dict_dados.get("exit code") != "0":
                    raise Exception(
                        f"Erro ao publicar o fluxo vazio: {dict_dados.get('exit code')}"
                    )
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = str(erro)
        finally:
            return (dict_dados, result_error)