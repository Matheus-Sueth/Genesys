from __future__ import annotations
import os
import re
import json
import yaml
from genesys.api import Genesys
from dataclasses import dataclass
from typing import Optional
import pkg_resources


@dataclass
class Task:
    name: str
    refId: str
    variables: Optional[dict] = None
    actions: Optional[list] = None


@dataclass
class InboundCall:
    name: str
    description: str
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
    variables: Optional[dict] = None
    tasks: Optional[list[Task]] = None
    menus: Optional[list] = None


class FileYaml:
    def __init__(self, path_file: str) -> None:
        self.path_file = path_file
        with open(self.path_file, 'rb') as arq_file:
            file = arq_file.read().decode('utf-8')
        file_genesys = file.replace('\t', '')
        self.file_genesys_txt = file_genesys
        self.json_file = json.loads(self.yaml_to_json(file_genesys))
        self.flow_type = list(self.json_file.keys())[0]
        if self.flow_type == 'inboundCall':
            tasks = [Task(**task['task']) for task in self.json_file[self.flow_type]['tasks']]
            aux = self.json_file
            aux[self.flow_type]['tasks'] = tasks
            self.flow = InboundCall(**aux[self.flow_type])
        else:
            self.flow = None

    def trocar_dados(self, variavel_antiga: str, varivel_nova: str) -> None:
        self.file_genesys_txt = self.file_genesys_txt.replace(variavel_antiga, varivel_nova)
        self.json_file = json.loads(self.yaml_to_json(self.file_genesys_txt))

    def yaml_to_json(self, yaml_string: str) -> str:
        data = yaml.safe_load(yaml_string)
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def save_yaml_to_file(self, yaml_file_path: str) -> None:
        with open(yaml_file_path, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(self.json_file, yaml_file, default_flow_style=False, allow_unicode=True)

    def quebrar_dicionario_transfer_to_flow(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:
                    case 'callCommonModule':
                        lista.append(list(valor['commonModule'].keys())[0])
                        continue
                    case 'transferToFlow':
                        lista.append(valor['targetFlow']['name'])            
                    case 'decision':
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_transfer_to_flow(action, lista)
                    case 'switch':
                        for case in valor['evaluate']['firstTrue']['cases']:
                            for action in case['case']['actions']:
                                self.quebrar_dicionario_transfer_to_flow(action, lista)
                        else:
                            if valor['evaluate']['firstTrue'].get('default'):
                                for action in valor['evaluate']['firstTrue']['default']['actions']:
                                    self.quebrar_dicionario_transfer_to_flow(action, lista)
                    case 'collectInput':
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_transfer_to_flow(action, lista)
                    case 'callData':
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_transfer_to_flow(action, lista)
                    case 'loop':
                        if valor.get('outputs'):
                            for action in valor['outputs']['loop']['actions']:
                                self.quebrar_dicionario_transfer_to_flow(action, lista)
                    case 'setParticipantData' | 'jumpToTask' | 'updateData' | 'playAudio' | 'disconnect' | 'getParticipantData' | 'setWhisperAudio' | 'flushAudio' | 'detectSilence' | 'playAudioOnSilence' | 'setSecuredData' | 'getSecuredData' | 'encryptData' | 'decryptData' | 'setUUIData' | 'setExternalTag' | 'getSIPHeaders' | 'getRawSIPHeaders' | 'dataTableLookup' | 'dialByExtension' | 'getExternalOrganization' | 'getExternalContact' | 'findUtilizationLabel' | 'findUsersById' | 'findUserPrompt' | 'findUserById' | 'findUser' | 'findSystemPrompt' | 'findSkill' | 'findScheduleGroup' | 'findSchedule' | 'findQueueById' | 'findQueue' | 'findLanguageSkill' | 'findGroup' | 'findEmergencyGroup' | 'setWrapupCode' | 'setUtilizationLabel' | 'setScreenPop' | 'setLanguage' | 'setFlowOutcome' | 'initializeFlowOutcome' | 'enableParticipantRecord' | 'createCallback' | 'clearUtilizationLabel' | 'addFlowMilestone' | 'evaluateScheduleGroup' | 'evaluateSchedule' | 'loopExit' | 'loopNext' | 'previousMenu' | 'jumpToMenu' | 'endTask' | 'callTask' | 'jumpToTask':
                        continue
                    case _:
                        continue 
            return lista
        except Exception as erro:
            raise Exception(f'Ocorreu um erro: {erro}\nAction: {action}')

    def quebrar_dicionario_call_data(self, action, lista: list) -> list:
        try:
            for chave, valor in action.items():
                match chave:            
                    case 'decision':
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_call_data(action, lista)
                    case 'switch':
                        for case in valor['evaluate']['firstTrue']['cases']:
                            for action in case['case']['actions']:
                                self.quebrar_dicionario_call_data(action, lista)
                        else:
                            if valor['evaluate']['firstTrue'].get('default'):
                                for action in valor['evaluate']['firstTrue']['default']['actions']:
                                    self.quebrar_dicionario_call_data(action, lista)
                    case 'collectInput':
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_call_data(action, lista)
                    case 'callData':
                        category = list(valor['category'].keys())[0]
                        name_data_action = list(valor['category'][category]['dataAction'].keys())[0]
                        lista.append((category, name_data_action))
                        if valor.get('outputs'):
                            for saidas in valor['outputs'].values():
                                for action in saidas['actions']:
                                    self.quebrar_dicionario_call_data(action, lista)
                    case 'loop':
                        if valor.get('outputs'):
                            for action in valor['outputs']['loop']['actions']:
                                self.quebrar_dicionario_call_data(action, lista)
                    case 'transferToFlow' | 'callCommonModule' | 'setParticipantData' | 'jumpToTask' | 'updateData' | 'playAudio' | 'disconnect' | 'getParticipantData' | 'setWhisperAudio' | 'flushAudio' | 'detectSilence' | 'playAudioOnSilence' | 'setSecuredData' | 'getSecuredData' | 'encryptData' | 'decryptData' | 'setUUIData' | 'setExternalTag' | 'getSIPHeaders' | 'getRawSIPHeaders' | 'dataTableLookup' | 'dialByExtension' | 'getExternalOrganization' | 'getExternalContact' | 'findUtilizationLabel' | 'findUsersById' | 'findUserPrompt' | 'findUserById' | 'findUser' | 'findSystemPrompt' | 'findSkill' | 'findScheduleGroup' | 'findSchedule' | 'findQueueById' | 'findQueue' | 'findLanguageSkill' | 'findGroup' | 'findEmergencyGroup' | 'setWrapupCode' | 'setUtilizationLabel' | 'setScreenPop' | 'setLanguage' | 'setFlowOutcome' | 'initializeFlowOutcome' | 'enableParticipantRecord' | 'createCallback' | 'clearUtilizationLabel' | 'addFlowMilestone' | 'evaluateScheduleGroup' | 'evaluateSchedule' | 'loopExit' | 'loopNext' | 'previousMenu' | 'jumpToMenu' | 'endTask' | 'callTask' | 'jumpToTask':
                        continue
                    case _:
                        continue 
            return lista
        except Exception as erro:
            raise Exception(f'Ocorreu um erro: {erro}\nAction: {action}')

    def get_flows_dependencies(self) -> list:
        flows = []
        if self.flow_type == 'inboundCall':
            for task in self.flow.tasks:
                for action in task.actions:
                    result = self.quebrar_dicionario_transfer_to_flow(action, list())
                    flows.extend(result)
        return sorted(list(set(flows)))


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
            status, error = None, None
            file_flow = FileYaml(flow_file)
            flow_name = file_flow.json_file[file_flow.flow_type]['name']
            if self.verificar_flow_prd(flow_name):
                raise Exception(f'Fluxo: {flow_name} é utilizado nos ivrs de produção')
            flows_dependencies = file_flow.get_flows_dependencies()
            [self.publish_flow_empty(flow_name_dependencie) for flow_name_dependencie in flows_dependencies if self.api.architect_api.get_flows(name=flow_name_dependencie).total == 0] 
            status = os.system(fr'archy publish --file "{flow_file}" --clientId {self.CLIENT_ID} --clientSecret {self.CLIENT_SECRET} --location {self.LOCATION}')
            assert status == 0
        except Exception as error:
            print(f'{error=}')
        finally:
            return (status, self.description_publish_flow[status].format(flow_name=flow_name, flow_type=file_flow.flow_type, error=error), file_flow)
        
    def publish_flow_empty(self, flow_name, description='Fluxo_Vazio'):
        try:
            status, error = None, None
            flow_file_name = pkg_resources.resource_filename('genesys', 'inbound_call_start.yaml')
            file_flow = FileYaml(flow_file_name)
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
            return (status, self.description_publish_flow[status].format(flow_name=flow_name, error=error), file_flow)