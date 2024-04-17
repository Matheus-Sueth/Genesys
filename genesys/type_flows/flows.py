from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional


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
        
    def get_dependencies(self, type_action: str) -> list:
        dados = []
        for task in self.tasks:
            for action in task.actions:
                match type_action:
                    case 'flows':
                        result = self.quebrar_dicionario_transfer_to_flow(action, list())
                    case 'data_actions':
                        result = self.quebrar_dicionario_call_data(action, list())
                    case _:
                        pass
                dados.extend(result)
        return sorted(list(set(dados)))

    def class_asdict(self) -> dict:
        data = {'inboundCall': {}}
        for chave, valor in asdict(self).items():
            if valor is not None:
                data['inboundCall'][chave] = valor
        #tasks = [{'task':asdict(task)} for task in self.tasks]
        tasks = []
        for task in self.tasks:
            aux_task = {'task':{}}
            for chave, valor in asdict(task).items():
                if valor is not None:
                    aux_task['task'][chave] = valor
            if aux_task:
                tasks.append(aux_task)

        if task:
            data['inboundCall']['tasks'] = tasks
        else:
            if data['inboundCall'].get('tasks'):
                del data['inboundCall']['tasks']
        return data


@dataclass
class InboundShortMessage:
    name: str
    description: str
    division: str
    startUpRef: str
    initialGreeting: dict
    defaultLanguage: str
    supportedLanguages: dict
    settingsErrorHandling: dict
    variables: Optional[dict] = None
    tasks: Optional[list[Task]] = None
    states: Optional[list[State]] = None
