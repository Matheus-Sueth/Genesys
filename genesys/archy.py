from __future__ import annotations
import importlib.resources as imp_res
import json
import os
import re
import subprocess
import tempfile
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Optional
import yaml
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
        self.path_file = path_file
        if isinstance(path_file, str):
            path = path_file
            if not os.path.exists(path):
                raise FileNotFoundError(f"Arquivo não encontrado: {path}")
            with open(path, "rb") as arq_file:
                file_txt = arq_file.read().decode("utf-8")
        else:
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
            nome = getattr(path, "name", "<resource>")
            try:
                size_bytes = len(path.read_bytes())
            except Exception:
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

    @property
    def metadata(self) -> dict:
        """Metadata mínima, disponível inclusive para tipos ainda não modelados em genesys.flows."""
        root = self.json_file.get(self.flow_type) or {}
        return {
            "flow_type": self.flow_type,
            "name": root.get("name"),
            "description": root.get("description"),
            "division": root.get("division"),
            "default_language": root.get("defaultLanguage"),
        }

    def trocar_dados(self, variavel_antiga: str, varivel_nova: str) -> None:
        self.file_genesys_txt = self.file_genesys_txt.replace(
            variavel_antiga, varivel_nova
        )
        self.json_file = json.loads(self.yaml_to_json())
        self.auxiliar = json.loads(self.yaml_to_json())
        self.definir_flow()

    def yaml_to_json(self) -> str:
        data = yaml.safe_load(self.file_genesys_txt)
        if not isinstance(data, dict) or not data:
            raise ValueError("O YAML precisa possuir um objeto raiz de flow.")
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save_yaml_to_file(self, output_path: str | None = None) -> "FileYaml":
        if self.flow is None:
            raise Exception("Nao existe variavel self.flow")
        if isinstance(self.path_file, str):
            target = self.path_file if output_path is None else output_path
        else:
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
                sort_keys=False,
            )
        return FileYaml(target)


class ArchyRuntime(str, Enum):
    """Onde o binário do Archy será executado."""

    LOCAL = "local"
    DOCKER = "docker"
    COMPOSE = "compose"


class DependencyMode(str, Enum):
    STRICT = "strict"
    CREATE_PLACEHOLDER = "create_placeholder"


@dataclass
class ArchyDependency:
    resource_type: str
    name: str
    genesys_type: Optional[str] = None
    exists: Optional[bool] = None
    created: bool = False
    error: Optional[str] = None


@dataclass
class ArchyCommandResult:
    ok: bool
    operation: str
    exit_code: int
    job_id: str
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    flow_name: Optional[str] = None
    flow_type: Optional[str] = None
    error_code: Optional[str] = None
    error_summary: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    dependencies: list[ArchyDependency] = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class ArchyExportResult:
    # Mantido para compatibilidade com a API anterior.
    ok: bool
    exit_code: int
    job_id: str
    export_file_host: Optional[str]
    stdout: str
    stderr: str


class Archy:
    """Gateway de alto nível para o Archy.

    Para o CX Forge, a recomendação é usar ``runtime='local'`` dentro de um
    worker cuja imagem já contenha o binário do Archy. Isso evita montar o
    Docker socket dentro da aplicação.

    ``runtime='docker'`` e ``runtime='compose'`` permanecem disponíveis para
    desenvolvimento/uso standalone.
    """

    padrao = re.compile(r"_v\d+-\d+\.yaml$")

    def __init__(
        self,
        genesys: Genesys,
        compose_file: str = "docker-compose.yml",
        compose_service: str = "app-genesys",
        volume_hint: str = "archy_out",
        host_exports_dir: str = "flows",
        *,
        runtime: ArchyRuntime | str = ArchyRuntime.LOCAL,
        archy_binary: str = "archy",
        docker_image: str = "genesys/archy:2.36.0",
        default_timeout_seconds: int = 300,
    ) -> None:
        self.api = genesys
        self.location = genesys.region.suffix
        self.compose_file = compose_file
        self.compose_service = compose_service
        self.volume_hint = volume_hint
        self.host_exports_dir = host_exports_dir
        self.runtime = ArchyRuntime(runtime)
        self.archy_binary = archy_binary
        self.docker_image = docker_image
        self.default_timeout_seconds = default_timeout_seconds

    def __str__(self) -> str:
        return f"Archy({self.api}, runtime={self.runtime.value})"

    @staticmethod
    def get_file_flow(flow_name: str, flow_version: str, output_dir: str):
        arquivos = os.listdir(os.path.abspath(f"{output_dir}/"))
        if flow_version == "latest":
            flow_files = sorted(
                [arquivo for arquivo in arquivos if arquivo.startswith(flow_name)]
            )
        else:
            flow_files = [
                arquivo
                for arquivo in arquivos
                if flow_name in arquivo and flow_version in arquivo
            ]
        if not flow_files:
            raise ValueError("No flow files")
        return os.path.join(output_dir, flow_files[-1])

    @staticmethod
    def _new_job_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def _sanitize(value: str, secrets: list[str]) -> str:
        sanitized = value or ""
        for secret in secrets:
            if secret:
                sanitized = sanitized.replace(secret, "[REDACTED]")
        # Defesa adicional para logs que imprimam o argumento em formato textual.
        sanitized = re.sub(
            r"(--authToken(?:=|\s+))[^\s\"']+",
            r"\1[REDACTED]",
            sanitized,
            flags=re.IGNORECASE,
        )
        return sanitized

    def _run(
        self,
        cmd: list[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        secrets: Optional[list[str]] = None,
    ) -> tuple[int, str, str, bool]:
        timeout_seconds = timeout or self.default_timeout_seconds
        secrets = secrets or []
        try:
            p = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                shell=False,
            )
            return (
                p.returncode,
                self._sanitize(p.stdout or "", secrets),
                self._sanitize(p.stderr or "", secrets),
                False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return (
                124,
                self._sanitize(stdout, secrets),
                self._sanitize(stderr, secrets),
                True,
            )

    def _token_info(self) -> tuple[str, bool]:
        token = self.api.token_provider.get_access_token()
        is_client_credentials = False
        try:
            info = self.api.token_provider.token_info()
            is_client_credentials = info.get("type") == "ClientCredentials"
        except Exception:
            # Providers antigos podem não implementar token_info().
            pass
        return token, is_client_credentials

    def _auth_args(self, *, include_token_type: bool = False) -> tuple[list[str], str]:
        token, is_client_credentials = self._token_info()
        args = ["--authToken", token]
        if include_token_type:
            args.extend(
                [
                    "--authTokenIsClientCredentials",
                    "true" if is_client_credentials else "false",
                ]
            )
        args.extend(["--location", self.api.region.suffix])
        return args, token

    @staticmethod
    def _validate_flow_file(flow_file: str) -> Path:
        path = Path(flow_file).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Arquivo YAML não encontrado: {path}")
        if path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("O arquivo do Archy precisa possuir extensão .yaml ou .yml")
        return path

    def _runtime_file_command(
        self,
        *,
        operation: str,
        host_file: Path,
        job_id: str,
        extra_args: Optional[list[str]] = None,
    ) -> tuple[list[str], str, Optional[str]]:
        """Monta comando e devolve (cmd, file_arg, cwd).

        O arquivo é bind-mounted para runtimes Docker/Compose, evitando copiar
        YAML para volumes compartilhados e isolando execuções concorrentes.
        """
        extra_args = extra_args or []
        if self.runtime == ArchyRuntime.LOCAL:
            file_arg = str(host_file)
            return (
                [self.archy_binary, operation, "--file", file_arg, *extra_args],
                file_arg,
                None,
            )

        container_file = f"/work/jobs/{job_id}/input{host_file.suffix.lower()}"
        mount = f"{host_file}:{container_file}:ro"

        if self.runtime == ArchyRuntime.DOCKER:
            cmd = [
                "docker",
                "run",
                "--rm",
                "-i",
                "--entrypoint",
                "archy",
                "-v",
                mount,
                self.docker_image,
                operation,
                "--file",
                container_file,
                *extra_args,
            ]
            return cmd, container_file, None

        cmd = [
            "docker",
            "compose",
            "-f",
            self.compose_file,
            "run",
            "--rm",
            "-T",
            "-v",
            mount,
            "--entrypoint",
            "archy",
            self.compose_service,
            operation,
            "--file",
            container_file,
            *extra_args,
        ]
        return cmd, container_file, None

    def inspect_dependencies(self, flow_file: str) -> list[ArchyDependency]:
        """Inspeciona dependências já modeladas pela biblioteca.

        Nesta versão o contrato suporta dependências de flow/Common Module que
        ``genesys.flows`` já consegue expor. Outros recursos serão adicionados
        incrementalmente sem alterar o contrato retornado ao CX Forge.
        """
        path = self._validate_flow_file(flow_file)
        file_flow = FileYaml(str(path))
        dependencies: list[ArchyDependency] = []
        if file_flow.flow is None or not hasattr(file_flow.flow, "get_dependencies"):
            return dependencies

        try:
            flows = file_flow.flow.get_dependencies("flows") or []
        except Exception as exc:
            return [
                ArchyDependency(
                    resource_type="flow",
                    name="<dependency-parser>",
                    exists=None,
                    error=str(exc),
                )
            ]

        for dependency_name, dependency_type in flows:
            dependency = ArchyDependency(
                resource_type="flow",
                name=dependency_name,
                genesys_type=dependency_type,
            )
            try:
                response = self.api.get_flows(
                    flow_name_or_description=dependency_name,
                    type_flow=dependency_type,
                )
                dependency.exists = bool(response.get("total", 0))
            except Exception as exc:
                dependency.exists = None
                dependency.error = str(exc)
            dependencies.append(dependency)
        return dependencies

    def validate_flow(
        self,
        flow_file: str,
        *,
        timeout: Optional[int] = None,
    ) -> ArchyCommandResult:
        """Preflight local do YAML usando ``archy createImportFile``.

        Não altera o Genesys Cloud.
        """
        path = self._validate_flow_file(flow_file)
        parsed = FileYaml(str(path))
        job_id = self._new_job_id()

        with tempfile.TemporaryDirectory(prefix=f"archy-{job_id}-") as temp_dir:
            output_host = Path(temp_dir)
            if self.runtime == ArchyRuntime.LOCAL:
                extra = ["--outputDir", str(output_host), "--force"]
                cmd, _, cwd = self._runtime_file_command(
                    operation="createImportFile",
                    host_file=path,
                    job_id=job_id,
                    extra_args=extra,
                )
            else:
                container_output = f"/work/jobs/{job_id}/output"
                output_mount = f"{output_host}:{container_output}"
                cmd, _, cwd = self._runtime_file_command(
                    operation="createImportFile",
                    host_file=path,
                    job_id=job_id,
                    extra_args=["--outputDir", container_output, "--force"],
                )
                # Montagem adicional precisa entrar antes da imagem/serviço.
                insert_at = cmd.index("--entrypoint")
                cmd[insert_at:insert_at] = ["-v", output_mount]

            code, out, err, timed_out = self._run(cmd, cwd=cwd, timeout=timeout)

        return ArchyCommandResult(
            ok=code == 0,
            operation="validate",
            exit_code=code,
            job_id=job_id,
            stdout=out,
            stderr=err,
            timed_out=timed_out,
            flow_name=parsed.metadata.get("name"),
            flow_type=parsed.flow_type,
            error_code="ARCHY_TIMEOUT" if timed_out else (None if code == 0 else "ARCHY_VALIDATION_FAILED"),
            error_summary=("Tempo limite excedido durante validação." if timed_out else (err.strip() or out.strip() or None)) if code != 0 else None,
        )

    def create_flow(
        self,
        flow_file: str,
        *,
        timeout: Optional[int] = None,
    ) -> ArchyCommandResult:
        path = self._validate_flow_file(flow_file)
        parsed = FileYaml(str(path))
        job_id = self._new_job_id()
        auth_args, token = self._auth_args()
        cmd, _, cwd = self._runtime_file_command(
            operation="create",
            host_file=path,
            job_id=job_id,
            extra_args=auth_args,
        )
        code, out, err, timed_out = self._run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            secrets=[token],
        )
        return ArchyCommandResult(
            ok=code == 0,
            operation="create",
            exit_code=code,
            job_id=job_id,
            stdout=out,
            stderr=err,
            timed_out=timed_out,
            flow_name=parsed.metadata.get("name"),
            flow_type=parsed.flow_type,
            error_code="ARCHY_TIMEOUT" if timed_out else (None if code == 0 else "ARCHY_CREATE_FAILED"),
            error_summary=(err.strip() or out.strip() or None) if code != 0 else None,
        )

    def publish_flow(
        self,
        flow_file: str,
        *,
        dependency_mode: DependencyMode | str = DependencyMode.STRICT,
        prevent_production: bool = False,
        timeout: Optional[int] = None,
    ) -> ArchyCommandResult:
        path = self._validate_flow_file(flow_file)
        parsed = FileYaml(str(path))
        flow_name = parsed.metadata.get("name")
        job_id = self._new_job_id()
        mode = DependencyMode(dependency_mode)

        if not flow_name:
            return ArchyCommandResult(
                ok=False,
                operation="publish",
                exit_code=64,
                job_id=job_id,
                flow_type=parsed.flow_type,
                error_code="FLOW_NAME_NOT_FOUND",
                error_summary="Não foi possível identificar o nome do flow no YAML.",
            )

        if prevent_production and self.api.search_flow_is_prd(flow_name):
            return ArchyCommandResult(
                ok=False,
                operation="publish",
                exit_code=65,
                job_id=job_id,
                flow_name=flow_name,
                flow_type=parsed.flow_type,
                error_code="PRODUCTION_FLOW_BLOCKED",
                error_summary=f"Fluxo '{flow_name}' está associado a um IVR de produção.",
            )

        dependencies = self.inspect_dependencies(str(path))
        unresolved = [d for d in dependencies if d.exists is False]
        unknown = [d for d in dependencies if d.exists is None]

        if unknown:
            return ArchyCommandResult(
                ok=False,
                operation="publish",
                exit_code=66,
                job_id=job_id,
                flow_name=flow_name,
                flow_type=parsed.flow_type,
                dependencies=dependencies,
                error_code="DEPENDENCY_CHECK_FAILED",
                error_summary="Não foi possível validar todas as dependências do flow.",
            )

        if unresolved and mode == DependencyMode.STRICT:
            return ArchyCommandResult(
                ok=False,
                operation="publish",
                exit_code=67,
                job_id=job_id,
                flow_name=flow_name,
                flow_type=parsed.flow_type,
                dependencies=dependencies,
                error_code="DEPENDENCY_NOT_FOUND",
                error_summary="Existem dependências ausentes. O modo STRICT bloqueou o deploy.",
            )

        if unresolved and mode == DependencyMode.CREATE_PLACEHOLDER:
            for dependency in unresolved:
                result = self.publish_empty_flow(
                    dependency.name,
                    timeout=timeout,
                    prevent_production=prevent_production,
                )
                dependency.created = result.ok
                if result.ok:
                    dependency.exists = True
                else:
                    dependency.error = result.error_summary or result.stderr
            if any(d.exists is not True for d in dependencies):
                return ArchyCommandResult(
                    ok=False,
                    operation="publish",
                    exit_code=68,
                    job_id=job_id,
                    flow_name=flow_name,
                    flow_type=parsed.flow_type,
                    dependencies=dependencies,
                    error_code="DEPENDENCY_PLACEHOLDER_FAILED",
                    error_summary="Falha ao criar uma ou mais dependências placeholder.",
                )

        auth_args, token = self._auth_args()
        cmd, _, cwd = self._runtime_file_command(
            operation="publish",
            host_file=path,
            job_id=job_id,
            extra_args=auth_args,
        )
        code, out, err, timed_out = self._run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            secrets=[token],
        )
        return ArchyCommandResult(
            ok=code == 0,
            operation="publish",
            exit_code=code,
            job_id=job_id,
            stdout=out,
            stderr=err,
            timed_out=timed_out,
            flow_name=flow_name,
            flow_type=parsed.flow_type,
            dependencies=dependencies,
            error_code="ARCHY_TIMEOUT" if timed_out else (None if code == 0 else "ARCHY_PUBLISH_FAILED"),
            error_summary=(err.strip() or out.strip() or None) if code != 0 else None,
            details=self._parse_key_value_output(out),
        )

    def publish_empty_flow(
        self,
        flow_name: str,
        description: str = "Fluxo_Vazio",
        *,
        timeout: Optional[int] = None,
        prevent_production: bool = True,
    ) -> ArchyCommandResult:
        if prevent_production and self.api.search_flow_is_prd(flow_name):
            return ArchyCommandResult(
                ok=False,
                operation="publish_placeholder",
                exit_code=65,
                job_id=self._new_job_id(),
                flow_name=flow_name,
                flow_type="inboundCall",
                error_code="PRODUCTION_FLOW_BLOCKED",
                error_summary=f"Fluxo '{flow_name}' está associado a um IVR de produção.",
            )

        resource = imp_res.files("genesys").joinpath("inbound_call_start.yaml")
        with tempfile.TemporaryDirectory(prefix="archy-placeholder-") as temp_dir:
            target = Path(temp_dir) / "placeholder.yaml"
            target.write_text(resource.read_text(encoding="utf-8"), encoding="utf-8")
            file_flow = FileYaml(str(target))
            if file_flow.flow is None:
                return ArchyCommandResult(
                    ok=False,
                    operation="publish_placeholder",
                    exit_code=69,
                    job_id=self._new_job_id(),
                    flow_name=flow_name,
                    flow_type="inboundCall",
                    error_code="PLACEHOLDER_TEMPLATE_INVALID",
                    error_summary="Template inbound_call_start.yaml não pôde ser interpretado.",
                )
            file_flow.flow.name = flow_name
            file_flow.flow.description = description
            file_flow.save_yaml_to_file(str(target))
            result = self.publish_flow(
                str(target),
                dependency_mode=DependencyMode.STRICT,
                prevent_production=prevent_production,
                timeout=timeout,
            )
            result.operation = "publish_placeholder"
            return result

    def export_flow(
        self,
        *,
        flow_name: str,
        flow_type: str,
        flow_version: str = "latest",
        export_type: str = "yaml",
        project_dir: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> tuple[ArchyExportResult, Optional[FileYaml]]:
        job_id = self._new_job_id()
        base = Path(project_dir) if project_dir else Path.cwd()
        export_dir_host = (base / self.host_exports_dir / job_id).resolve()
        export_dir_host.mkdir(parents=True, exist_ok=True)
        auth_args, token = self._auth_args(include_token_type=True)

        if self.runtime == ArchyRuntime.LOCAL:
            output_arg = str(export_dir_host)
            cmd = [
                self.archy_binary,
                "export",
                "--flowName",
                flow_name,
                "--flowType",
                flow_type,
                "--flowVersion",
                flow_version,
                "--exportType",
                export_type,
                "--outputDir",
                output_arg,
                *auth_args,
            ]
            cwd = str(base)
        else:
            container_output = f"/work/exports/{job_id}"
            mount = f"{export_dir_host}:{container_output}"
            archy_args = [
                "export",
                "--flowName",
                flow_name,
                "--flowType",
                flow_type,
                "--flowVersion",
                flow_version,
                "--exportType",
                export_type,
                "--outputDir",
                container_output,
                *auth_args,
            ]
            if self.runtime == ArchyRuntime.DOCKER:
                cmd = [
                    "docker",
                    "run",
                    "--rm",
                    "-i",
                    "--entrypoint",
                    "archy",
                    "-v",
                    mount,
                    self.docker_image,
                    *archy_args,
                ]
                cwd = None
            else:
                cmd = [
                    "docker",
                    "compose",
                    "-f",
                    self.compose_file,
                    "run",
                    "--rm",
                    "-T",
                    "-v",
                    mount,
                    "--entrypoint",
                    "archy",
                    self.compose_service,
                    *archy_args,
                ]
                cwd = str(base)

        code, out, err, _ = self._run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            secrets=[token],
        )
        if code != 0:
            return (
                ArchyExportResult(
                    ok=False,
                    exit_code=code,
                    job_id=job_id,
                    export_file_host=None,
                    stdout=out,
                    stderr=err,
                ),
                None,
            )

        yaml_files = sorted(export_dir_host.glob("*.yaml"))
        export_file_host = str(yaml_files[0].resolve()) if yaml_files else None
        ok = export_file_host is not None
        result = ArchyExportResult(
            ok=ok,
            exit_code=0 if ok else 70,
            job_id=job_id,
            export_file_host=export_file_host,
            stdout=out,
            stderr=err,
        )
        return (result, FileYaml(export_file_host) if export_file_host else None)

    @staticmethod
    def _parse_key_value_output(output: str) -> dict:
        parsed: dict[str, str] = {}
        for line in (output or "").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key:
                parsed[key] = value.strip()
        return parsed

    # ------------------------------------------------------------------
    # Compatibilidade com a API antiga
    # ------------------------------------------------------------------
    def publish_flow_subprocess(self, flow_file):
        """Compatibilidade temporária. Prefira :meth:`publish_flow`.

        Mantém o comportamento antigo de tentar criar placeholders e bloquear
        flows identificados pela biblioteca como utilizados em IVR de produção.
        """
        result = self.publish_flow(
            flow_file,
            dependency_mode=DependencyMode.CREATE_PLACEHOLDER,
            prevent_production=True,
        )
        data = dict(result.details)
        data["dependencies"] = [d.__dict__ for d in result.dependencies]
        data.setdefault("exit code", str(result.exit_code))
        error = None if result.ok else (result.error_summary or result.stderr or result.error_code)
        return data, error

    def publish_flow_empty_subprocess(
        self, flow_name, description="Fluxo_Vazio"
    ) -> tuple[dict | None, str | None]:
        """Compatibilidade temporária. Prefira :meth:`publish_empty_flow`."""
        result = self.publish_empty_flow(flow_name, description)
        data = dict(result.details)
        data.setdefault("exit code", str(result.exit_code))
        error = None if result.ok else (result.error_summary or result.stderr or result.error_code)
        return data, error
