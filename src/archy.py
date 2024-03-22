import os
import re
import json
import yaml
from dotenv import load_dotenv
from .api import Genesys

load_dotenv()


class FileYaml:
    def __init__(self, path_file: str) -> None:
        self.path_file = path_file
        with open(self.path_file, 'rb') as arq_file:
            file = arq_file.read().decode('utf-8')
        file_genesys = file.replace('\t', '')
        self.file_genesys_txt = file_genesys
        self.json_file = json.loads(self.yaml_to_json(file_genesys))

    def trocar_dados(self, variavel_antiga: str, varivel_nova: str) -> None:
        self.file_genesys_txt = self.file_genesys_txt.replace(variavel_antiga, varivel_nova)
        self.json_file = json.loads(self.yaml_to_json(self.file_genesys_txt))

    def yaml_to_json(self, yaml_string: str) -> str:
        data = yaml.safe_load(yaml_string)
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def save_yaml_to_file(self, yaml_file_path: str) -> None:
        with open(yaml_file_path, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(self.json_file, yaml_file, default_flow_style=False, allow_unicode=True)
    

class Archy:
    description_export_flow = {
    0: "Sucesso",
    100: "the flow named ({flow_name}) of type ({flow_type}) does not exist.",
    101: "Architect Scripting errors will be listed above.",
    106: "no value specified for the ({flow_name}) parameter",
    109: "the export file at ({flow_name}) exists and will not be overwritten."
    }
    description_publish_flow = {
    0: "Sucesso",
    100: "the flow called ({flow_name}) of type ({flow_type}) has a schema error: ({error}).",
    101: "Architect Scripting errors will be listed above.",
    123: "the flow called ({flow_name}) of type ({flow_type}) has a validation error: ({error})."
    }
    padrao = re.compile(r'_v\d+-\d+\.yaml$')

    DADOS = json.loads(os.environ.get('DADOS'))

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
    
    def verificar_flow_prd(self, flow_name_or_id: str):
        ivr_objects = self.api.architect_api.get_architect_ivrs()
        for ivr in ivr_objects.entities:
            flow_id = ivr.open_hours_flow.id
            flow_name = ivr.open_hours_flow.name
            if flow_name_or_id in (flow_id, flow_name):
                return True
        return False
    
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
            error = None
            file_flow = FileYaml(flow_file)
            flow_type = list(file_flow.json_file.keys())[0]
            flow_name = file_flow.json_file[flow_type]['name']
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            status = os.system(fr'C:\Users\matheus.mendonca\archy\archy publish --file "{flow_file}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
            assert status == 0
        except Exception as error:
            print(f'{error=}')
        finally:
            return (status, self.description_publish_flow[status].format(flow_name=flow_name, flow_type=flow_type, error=error), file_flow)
        
    def publish_flow_empty(self, flow_file_name_2, description='Fluxo_Vazio'):
        try:
            flow_file_name = r'C:\Users\matheus.mendonca\AppData\Local\Programs\Python\Python312\Lib\Genesys\inbound_call_start.yaml'
            file_flow = FileYaml(flow_file_name)
            file_flow_2 = FileYaml(flow_file_name_2)
            flow_name =  file_flow_2.json_file['inboundCall']['name'] 
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            file_flow.json_file['inboundCall']['name'] = flow_name
            file_flow.json_file['inboundCall']['description'] = description
            file_flow.save_yaml_to_file(flow_file_name)
            status = os.system(f'archy publish --file {flow_file_name} --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
            assert status == 0
        except Exception as error:
            print(f'{error=}')
        finally:
            return (status, flow_file_name_2, flow_name)
 


