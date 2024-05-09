from __future__ import annotations
import os
import re
import json
import yaml
from genesys.api import Genesys
from genesys.thread import Thread
import pkg_resources
import subprocess
import genesys.type_flows.flows as tf_flow


class FileYaml:
    def __init__(self, path_file: str) -> None:
        self.path_file = path_file
        with open(self.path_file, 'rb') as arq_file:
            file = arq_file.read().decode('utf-8')
        self.file_genesys_txt = file.replace('\t', '')
        self.json_file = json.loads(self.yaml_to_json())
        self.auxiliar = json.loads(self.yaml_to_json())
        self.definir_flow()

    def definir_flow(self):
        self.flow_type = list(self.json_file.keys())[0]
        if self.flow_type == 'inboundCall':
            tasks = [tf_flow.Task(**task['task']) for task in self.json_file[self.flow_type]['tasks']]
            del self.auxiliar[self.flow_type]['tasks']
            self.flow = tf_flow.InboundCall(**self.auxiliar[self.flow_type], tasks=tasks)
        elif self.flow_type == 'inboundShortMessage':
            states = [tf_flow.Task(**state['state']) for state in self.json_file[self.flow_type]['states']]
            tasks = [tf_flow.Task(**task['task']) for task in self.json_file[self.flow_type]['tasks']]
            del self.auxiliar[self.flow_type]['tasks']
            del self.auxiliar[self.flow_type]['states']
            self.flow = tf_flow.InboundShortMessage(**self.auxiliar[self.flow_type], states=states, tasks=tasks)
        else:
            self.flow = None

    def trocar_dados(self, variavel_antiga: str, varivel_nova: str) -> None:
        self.file_genesys_txt = self.file_genesys_txt.replace(variavel_antiga, varivel_nova)
        self.json_file = json.loads(self.yaml_to_json())
        self.auxiliar = json.loads(self.yaml_to_json())
        self.definir_flow()

    def yaml_to_json(self) -> str:
        data = yaml.safe_load(self.file_genesys_txt)
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def save_yaml_to_file(self) -> FileYaml:        
        with open(self.path_file, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(self.flow.class_asdict(), yaml_file, default_flow_style=False, allow_unicode=True)
        return FileYaml(self.path_file)


class Archy:
    description_export_flow = {
    0: "Sucesso",
    99: "Architect Scripting returned an error during Archy command execution.",
    100: "the flow named ({flow_name}) of type ({flow_type}) does not exist.",
    101: "Architect Scripting errors will be listed above.",
    106: "no value specified for the ({flow_name}) parameter",
    109: "the export file at ({flow_name}) exists and will not be overwritten."
    }
    description_publish_flow = {
    0: "Sucesso",
    99: "Architect Scripting returned an error during Archy command execution.",
    100: "the flow called ({flow_name}) of type ({flow_type}) has a schema error: ({error}).",
    101: "Architect Scripting errors will be listed above.",
    123: "the flow called ({flow_name}) of type ({flow_type}) has a validation error: ({error})."
    }
    padrao = re.compile(r'_v\d+-\d+\.yaml$')

    DADOS = Genesys.DADOS

    def __init__(self, org: str) -> None:
        if org not in self.DADOS.keys():
            raise ValueError('Organização Desconhecida')
        self.LOCATION = self.DADOS[org]['URL_AUTH']
        self.CLIENT_ID = self.DADOS[org]['CLIENT_ID']
        self.CLIENT_SECRET = self.DADOS[org]['CLIENT_SECRET']
        self.api = Genesys(org)
        
    def __new__(self, *args):
        if not hasattr(self, 'instance'):
            self.instance = super(Archy, self).__new__(self)
        return self.instance
    
    def get_file_flow(flow_name: str, flow_version: str, output_dir: str):
        arquivos = os.listdir(os.path.abspath(f'{output_dir}/'))
        if flow_version == 'latest':
            arquivos = os.listdir(os.path.abspath(f'{output_dir}/'))
            flow_files = [arquivo for arquivo in arquivos if arquivo.startswith(flow_name)].sort()
        else:
            flow_files = [arquivo for arquivo in arquivos if flow_name in arquivo and flow_version in arquivo]# Outra solução: list(filter(lambda arquivo: flow_name in arquivo and flow_version in arquivo,arquivos))
        if len(flow_files) == 0:
            raise ValueError("No flow filess")
        else:
            caminho_file = os.path.join(output_dir, flow_files[-1])

    def export_flow(self, flow_name: str, flow_type: str = 'inboundcall', flow_version: str = 'latest', output_dir: str = 'flows'):
        status = os.system(f'archy export --flowName "{flow_name}" --flowType {flow_type} --flowVersion {flow_version} --outputDir "{output_dir}" --exportType yaml --authTokenIsClientCredentials true --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
        try:
            flow_version = flow_version.replace(".","-")
            arquivos = os.listdir(os.path.abspath(f'{output_dir}/'))
            if status == 109:
                if flow_version == 'latest':
                    arquivos = os.listdir(os.path.abspath(f'{output_dir}/'))
                    flow_files = [arquivo for arquivo in arquivos if arquivo.startswith(flow_name)] 
                    flow_files.sort()
                else:
                    flow_files = [arquivo for arquivo in arquivos if flow_name in arquivo and flow_version in arquivo]# Outra solução: list(filter(lambda arquivo: flow_name in arquivo and flow_version in arquivo,arquivos))
                    assert len(flow_files) == 1
                if len(flow_files) == 0:
                    raise ValueError("No flow filess")
                else:
                    caminho_file = os.path.join(output_dir, flow_files[-1])
            else:
                datas_criacao = {}
                for arquivo in arquivos:
                    datas_criacao[arquivo] = os.path.getctime(os.path.abspath(os.path.join(output_dir, arquivo))) 
                arquivos_ordenados = sorted(datas_criacao.keys(), key=lambda x: datas_criacao[x])
                caminho_file = os.path.join(output_dir, arquivos_ordenados[-1])
            file_flow = FileYaml(os.path.abspath(caminho_file))
        except Exception as error:
            print(f'{error=}')
            file_flow = None
        finally:
            return (status, self.description_export_flow[status].format(flow_name=flow_name, flow_type=flow_type), file_flow)
    
    def publish_flow(self, flow_file):
        try:
            status, error = None, None
            file_flow = FileYaml(flow_file)
            flow_name = file_flow.flow.name
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            flows_dependencies = file_flow.get_dependencies('flows')
            [self.publish_flow_empty(flow_name_dependencie) for flow_name_dependencie, flow_type_dependencie in flows_dependencies if self.api.get_flows(flow_name_or_description=flow_name_dependencie, type_flow=flow_type_dependencie).total == 0] 
            status = os.system(fr'archy publish --file "{flow_file}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
            assert status == 0
        except Exception as error:
            print(f'{error=}')
        finally:
            return (status, self.description_publish_flow[status].format(flow_name=flow_name, flow_type=file_flow.flow_type, error=error), file_flow)
        
    def publish_flow_subprocess(self, flow_file):
        try:
            dict_dados, result_error = None, None
            file_flow = FileYaml(flow_file)
            flow_name = file_flow.flow.name
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            flows_dependencies = file_flow.flow.get_dependencies('flows')
            threads_list = []
            for flow_name_dependencie in flows_dependencies:
                if self.api.get_flows(flow_name_or_description=flow_name_dependencie).total == 0:
                    t = Thread(name=flow_name_dependencie, funcao=self.publish_flow_empty_subprocess, args=(flow_name_dependencie,), daemon=True)
                    t.start()
                    threads_list.append(t)
            for t in threads_list:
                t.join()
                tupla = t.get_resultado()
                if None is not tupla[1]:
                    raise Exception(f'Ocorreu um erro na função(publish_flow_empty_subprocess): {tupla=}')
                if None is not tupla[0] or tupla[0].get('exit code','-1') != '0':
                    raise Exception(f'Ocorreu um erro na função(publish_flow_empty_subprocess): {tupla=}')
            cmd = f'archy publish --file "{flow_file}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}'
            results, error = subprocess.Popen([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
            if results:
                dados = results.decode()
                lista_dados = [dado.split(':') for dado in dados.split('\n') if dado.strip() != "" and ':' in dado]
                dict_dados = {}
                for dado in lista_dados:
                    chave = dado[0].strip()
                    valor = ':'.join(dado[1:]).strip()
                    dict_dados[chave] = valor
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = erro
        finally:
            return (dict_dados, result_error)

    def publish_flow_empty(self, flow_name, description='Fluxo_Vazio'):
        try:
            status, error = None, None
            flow_file_name = pkg_resources.resource_filename('genesys', 'inbound_call_start.yaml')
            file_flow = FileYaml(flow_file_name)
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            file_flow.flow.name = flow_name
            file_flow.flow.description = description
            file_flow.save_yaml_to_file()
            status = os.system(f'archy publish --file "{flow_file_name}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
            assert status == 0
        except Exception as error:
            print(f'{error=}')
        finally:
            return (status, self.description_publish_flow[status].format(flow_name=flow_name, error=error), file_flow)
        
    def publish_flow_empty_subprocess(self, flow_name, description='Fluxo_Vazio') -> tuple[dict|None, str|None]:
        try:
            dict_dados, result_error = None, None
            flow_file_name = pkg_resources.resource_filename('genesys', 'inbound_call_start.yaml')
            file_flow = FileYaml(flow_file_name)
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            file_flow.flow.name = flow_name
            file_flow.flow.description = description
            file_flow.save_yaml_to_file()
            cmd = f'archy publish --file "{flow_file_name}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}'
            results, error = subprocess.Popen([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()
            if results:
                dados = results.decode()
                lista_dados = [dado.split(':') for dado in dados.split('\n') if dado.strip() != "" and ':' in dado]
                dict_dados = {}
                for dado in lista_dados:
                    chave = dado[0].strip()
                    valor = ':'.join(dado[1:]).strip()
                    dict_dados[chave] = valor
            if error:
                result_error = error.decode()
        except Exception as erro:
            result_error = erro
        finally:
            return (dict_dados, result_error)
 