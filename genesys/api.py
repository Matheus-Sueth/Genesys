import requests
import os
import json
import re
import time
import base64
from dotenv import dotenv_values


def json_for_class(class_name: str, dict_data: dict) -> object:
    class_new = type(class_name, (), {})

    def def_attribute(dicionario: object, classe: type) -> None:
        if not isinstance(dicionario, dict):
            print(dicionario)
            exit()
        for key, value in dicionario.items():
            if isinstance(value, dict):
                sub_classe = type(key.capitalize(), (), {})
                setattr(classe, key, sub_classe)
                if isinstance(value, dict):
                    def_attribute(value, sub_classe)
            elif isinstance(value, list):
                if all(not isinstance(item, dict) for item in value):
                    setattr(classe, key, value)
                else:
                    setattr(classe, key, [])
                    for index, item in enumerate(value):
                        sub_classe = type(f"{key[:-1].capitalize()}_{index}", (), {})
                        getattr(classe, key).append(sub_classe)
                        def_attribute(item, sub_classe)
                    
            else:
                setattr(classe, key, value)

    def __str__(self):
        atributos = ', '.join([f'{key}: {value}' for key, value in dict_data.items()])
        return f"{class_name}({atributos})"

    def_attribute(dict_data, class_new)
    setattr(class_new, '__str__', __str__)
    return class_new


vars_dotenv = dotenv_values(os.environ.get('DADOS'))


class Genesys:
    DADOS = json.loads(vars_dotenv.get('DADOS'))

    def __init__(self, org: str) -> None:
        self.org = org
        if org not in self.DADOS.keys():
            raise ValueError('Organização Desconhecida')
        self.URL = self.DADOS[org]['URL']
        self.URL_AUTH = self.DADOS[org]['URL_AUTH']
        self.CLIENT_ID = self.DADOS[org]['CLIENT_ID']
        self.CLIENT_SECRET = self.DADOS[org]['CLIENT_SECRET']
        self.token = self.get_token()

    def _check_and_update_token(self):
        """
        client.credentials.token.rate.per.minute | The maximum number of requests per client credentials grant token per minute | 300\n
        org.app.user.rate.per.minute | The maximum number of requests per organization per OAuth client per user per minute | 3000\n
        request.bytes.max | The maximum content length of a request payload | 512000\n
        token.rate.per.minute | The maximum number of requests per token per minute | 300
        """
        if time.time() - self._last_reset_time >= 60:
            self._call_count = 0
            self._last_reset_time = time.time()

        if self._call_count >= 3000:
            print("Atingido o limite de chamadas. Aguarde um minuto...")
            time.sleep(60)
            self._call_count = 0 
            self._last_reset_time = time.time()
            self._update_apis()
        else:
            self._call_count += 1
     
    def __new__(self, *args):
        if not hasattr(self, 'instance'):
            self.instance = super(Genesys, self).__new__(self)
        return self.instance
    
    def __str__(self):
        return f"APIs Genesys PureCloud utilizando o ambiente: {self.org}"

    def get_token(self) -> str:
        authorization = base64.b64encode(bytes(self.CLIENT_ID + ":" + self.CLIENT_SECRET, "ISO-8859-1")).decode("ascii")

        request_headers = {
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        request_body = {
            "grant_type": "client_credentials"
        }

        response = requests.post(f"https://login.{self.URL_AUTH}/oauth/token", data=request_body, headers=request_headers)

        if response.status_code == 200:
            response_json = response.json()
            return response_json['access_token']
        else:
            raise Exception(f"Failure: {response.status_code} - {response.reason}")

    def update_token(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.head(url='https://'+self.URL+'/api/v2/tokens/me', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return None

    def check_token(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.head(url='https://'+self.URL+'/api/v2/tokens/me', headers=headers)
        if not response.ok:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')

    def get_conversation_call_by_id(self, conversation_id: str) -> object:
        """
        GET /api/v2/conversations/calls/{conversationId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/conversations/calls/{conversation_id}', headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: get_conversation_call_by_id({conversation_id=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('CallConversation', response.json())
        data = class_new()
        return data
    
    def get_user_prompt_by_name_or_description(self, page_number: int = 1, page_size: int = 50,  name: list[str] = [''], description: str = '', name_or_description: str = '', language: list[str] = ['pt-br']) -> object:
        """
        GET /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/prompts', params=parameters, headers=headers)
        dados = response.json()
        if not response.ok or dados['total'] != 1:
            raise Exception(f'Falha na chamada: get_user_prompt_by_name_or_description({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('UserPrompt', dados['entities'][0])
        data = class_new()
        return data
    
    def get_user_prompts(self, page_number: int = 1, page_size: int = 50,  name: list[str] = [''], description: str = '', name_or_description: str = '', language: list[str] = ['pt-br']) -> object:
        """
        GET /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/prompts', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: get_user_prompts({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('UserPrompts', response.json())
        data = class_new()
        return data

    def get_system_prompts(self, page_number: int = 1, page_size: int = 50,  name: list[str] = [''], description: str = '', name_or_description: str = '', language: list[str] = ['pt-br']) -> object:
        """
        GET /api/v2/architect/systemprompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/systemprompts', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: get_system_prompts({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('SystemPrompts', response.json())
        data = class_new()
        return data

    def get_system_prompt_by_name_or_description(self, page_number: int = 1, page_size: int = 50,  name: list[str] = [''], description: str = '', name_or_description: str = '', language: list[str] = ['pt-br']) -> object:
        """
        GET /api/v2/architect/systemprompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/systemprompts', params=parameters, headers=headers)
        dados = response.json()
        if not response.ok or dados['total'] != 1:
            raise Exception(f'Falha na chamada: get_system_prompt_by_name_or_description({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('SystemPrompts', dados['entities'][0])
        data = class_new()
        return data   

    def get_data_table_by_name(self, name: str, page_number: int = 1, page_size: int = 50, expand: str = '') -> object:
        """
        GET /api/v2/flows/datatables/divisionviews HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/datatables/divisionviews', params=parameters, headers=headers)
        dados = response.json()
        if not response.ok or dados['total'] != 1:
            raise Exception(f'Falha na chamada: get_data_table_by_name({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('DataTable', dados['entities'][0])
        data = class_new()
        return data
    
    def get_data_tables(self, page_number: int = 1, page_size: int = 50, name: str = '', expand: str = '') -> object:
        """
        GET /api/v2/flows/datatables/divisionviews HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/datatables/divisionviews', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: get_data_tables({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('DataTables', response.json())
        data = class_new()
        return data

    def get_row_data_table_by_id(self, data_table_id: str, row_id: str) -> object:
        """
        GET /api/v2/flows/datatables/{datatableId}/rows/{rowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "showbrief": True
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/datatables/{data_table_id}/rows/{row_id}', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: get_row_data_table_by_id({data_table_id=}, {row_id=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('RowDataTable', response.json())
        data = class_new()
        return data

    def get_data_action_by_name(self, category_name: str, name_data_action: str, page_number: int = 1, page_size: int = 50) -> object:
        """
        GET /api/v2/integrations/actions HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "category": category_name,
            "name": name_data_action
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/integrations/actions', params=parameters, headers=headers)
        dados = response.json()
        if response.status_code != 200 and len(dados['entities']) != 1:
            raise Exception(f'Falha na chamada: get_data_action_by_name({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('DataAction', dados['entities'][0])
        data = class_new()
        return data

    def execute_data_action(self, data_action_id: str, body: dict, tempo_timeout: int = 60) -> tuple[dict, str]:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        try:
            status = ''
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.token}"
            }
            response = requests.post(url='https://'+self.URL+f'/api/v2/integrations/actions/{data_action_id}/test', headers=headers, data=json.dumps(body), timeout=tempo_timeout)
            status = response.status_code
            class_new = json_for_class(f'custom_{data_action_id}', response.json())
            dados = class_new()
            if response.ok:
                return (dados, 'success')
            elif status == 408 or status == 504:
                return (dados, 'timeout')
            return (dados, 'failure')
        except requests.exceptions.ReadTimeout:
            return ({},'timeout')
        except Exception as erro:
            raise Exception(f'Falha na chamada: get_data_action_by_name({data_action_id=}, {body=}, {tempo_timeout=})\nstatus_code: {response.status_code}\ntext: {response.text}\nerro: {erro}\n')

    def get_ivr_by_id(self, ivr_id: str) -> object:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/ivrs/{ivr_id}', headers=headers)
        dados = response.json()
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_ivr_by_id({ivr_id=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Ivr', dados['entities'][0])
        data = class_new()
        return data

    def get_ivrs(self, name: str = '', dnis: str = '', schedule_group: str = '', page_number: int = 1, page_size: int = 50) -> object:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "sortBy": "name",
            "sortOrder": "asc",
            "name": name,
            "dnis": dnis,
            "scheduleGroup": schedule_group
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/ivrs', headers=headers, params=parameters)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_ivrs({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Ivrs', response.json())
        data = class_new()
        return data

    def get_did_pool_by_number(self, number_match: str) -> object:
        """
        GET /api/v2/telephony/providers/edges/didpools/dids HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "numberMatch": number_match,
            "type": "ASSIGNED_AND_UNASSIGNED"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/telephony/providers/edges/didpools/dids', headers=headers, params=parameters)
        dados = response.json()
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_did_pool_by_number({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('DidPool', dados['entities'][0])
        data = class_new()
        return data

    def get_flow_by_id(self, flow_id: str) -> object:
        """
        GET /api/v2/flows/{flowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/{flow_id}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_flow_by_id({flow_id=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Flow', response.json())
        data = class_new()
        return data

    def get_flows(self, flow_name_or_description: str, page_number: int = 1, page_size: int = 50, type_flow: str = 'inboundcall') -> object:
        """
        GET /api/v2/flows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "sortBy": "name",
            "sortOrder": "asc",
            "includeSchemas": "true",
            "nameOrDescription": f'*{flow_name_or_description}*',
            "type": type_flow
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows', headers=headers, params=parameters)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_flows({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Flows', response.json())
        data = class_new()
        return data

    def get_flow_by_name(self, flow_name: str, page_number: int = 1, page_size: int = 50) -> object:
        """
        GET /api/v2/flows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": flow_name
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows', headers=headers, params=parameters)
        dados = response.json()
        if not response.ok or dados['total'] != 1:
            raise Exception(f'Falha na chamada: get_data_table_by_name({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Flow', dados['entities'][0])
        data = class_new()
        return data

    def create_new_user_prompt(self, name: str, description: str) -> object:
        """
        POST /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        body = {
            "name": name,
            "description": description
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/architect/prompts', headers=headers, data=json.dumps(body))
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: create_new_user_prompt({body=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('UserPrompt', response.json())
        data = class_new()
        return data

    def create_new_user_prompt_resource(self, prompt_id: str, language: str, ttsString: str, text: str) -> object:
        """
        POST /api/v2/architect/prompts/{promptId}/resources HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        body = {
            "language": language,
            "ttsString": ttsString,
            "text": text
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/architect/prompts/{prompt_id}/resources', headers=headers, data=json.dumps(body))
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: create_new_user_prompt_resource({body=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('UserPromptResource', response.json())
        data = class_new()
        return data

    def get_version_last_flow_by_name(self, flow_name) -> int:
        fluxos = []
        page_number = 1
        while True:
            dados = self.get_flows(flow_name_or_description=flow_name, page_number=page_number)
            if len(fluxos) >= dados.total:
                break
            fluxos.extend([re.search(r'v(\d+)', fluxo.name) for fluxo in dados.entities])
            page_number += 1
        return max([int(match.group(1)) for match in fluxos])
    
    def upload_user_prompt_resource_by_url(self, upload_url: str, file_name: str, file_path: str) -> dict:
        """
        Upload file a user prompt resource

        POST upload_url HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        try:
            headers = {
                "Authorization": f"bearer {self.token}"
            }
            wav_form_data = {
                'file': (file_name, open(file_path, 'rb'))
            }

            response = requests.post(upload_url, files=wav_form_data, headers=headers)
            if not response.ok:
                raise Exception(f'Failure: {response.status_code} - {response.reason}')
            return response.json()
        except Exception as error:
            raise Exception(f'Falha na chamada(upload_user_prompt_resource_by_url({upload_url=}, {file_name=}, {file_path=}))\n{error=}')

    def get_user_by_name(self, user_name: str, page_number: int = 1, page_size: int = 20) -> object:
        """
        POST /api/v2/users/search HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        body = {"pageSize": page_size,"pageNumber": page_number,"query":[{"type":"EXACT","fields":["state"],"values":["active","inactive"]},{"type":"QUERY_STRING","fields":["name"],"value":user_name}],"sortOrder":"ASC","sortBy":"name","expand":["authorization","team"],"enforcePermissions":True}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/users/search', data=json.dumps(body), headers=headers)
        dados = response.json()
        if response.status_code != 200 and len(dados['total']) < 1:
            raise Exception(f'Falha na chamada: get_user_by_email({body=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('User', dados['results'])
        data = class_new()
        return data

    def get_user_by_email(self, user_email: str, page_number: int = 1, page_size: int = 20) -> object:
        """
        POST /api/v2/users/search HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        body = {"pageSize": page_size,"pageNumber": page_number,"query":[{"type":"EXACT","fields":["state"],"values":["active","inactive"]},{"type":"QUERY_STRING","fields":["email"],"value":user_email}],"sortOrder":"ASC","sortBy":"name","expand":["images","authorization","team"],"enforcePermissions":True}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/users/search', data=json.dumps(body), headers=headers)
        dados = response.json()
        if response.status_code != 200 and len(dados['total']) < 1:
            raise Exception(f'Falha na chamada: get_user_by_email({body=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('User', dados['results'])
        data = class_new()
        return data

    def set_new_password_for_user_by_user_id(self, user_id: str, new_password: str) -> None:
        """
        POST /api/v2/users/{userId}/password HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        body = {
        "newPassword": new_password
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/users/{user_id}/password', data=json.dumps(body), headers=headers)
        if response.status_code != 204:
            raise Exception(f'Falha na chamada: set_new_password_for_user_by_user_id({user_id=}, {new_password=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
            
    def get_recipients_routing(self, page_number: int = 1, page_size: int = 20) -> object:
        """
        GET /api/v2/routing/message/recipients HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/routing/message/recipients', params=parameters, headers=headers)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_user_by_email({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('RecipientsMessage', response.json())
        data = class_new()
        return data

    def search_flow_prd_by_name_or_id(self, flow_name_or_id: str) -> bool:
        ivr_objects = self.get_ivrs()
        for ivr in ivr_objects.entities:
            flow_id = ivr.openHoursFlow.id
            flow_name = ivr.openHoursFlow.name
            if flow_name_or_id in (flow_id, flow_name):
                return True
            
        ivr_objects = self.get_recipients_routing()
        for ivr in ivr_objects.entities:
            flow_id = ivr.flow.id
            flow_name = ivr.flow.name
            if flow_name_or_id in (flow_id, flow_name):
                return True
        return False

    def checkin_flow_by_id(self, flow_id: str) -> object:
        """
        POST /api/v2/flows/actions/checkin HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        parameters = {
            "flow": flow_id
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/flows/actions/checkin', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: checkin_flow_by_id({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('CheckinResponse', response.json())
        data = class_new()
        return data
    
    def checkout_flow_by_id(self, flow_id: str) -> object:
        """
        POST /api/v2/flows/actions/checkout HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        parameters = {
            "flow": flow_id
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/flows/actions/checkout', params=parameters, headers=headers)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: checkout_flow_by_id({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('Flow', response.json())
        data = class_new()
        return data
    
    def publish_flow_by_id(self, flow_id: str) -> object:
        """
        POST /api/v2/flows/actions/publish HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        parameters = {
            "flow": flow_id
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.post(url='https://'+self.URL+f'/api/v2/flows/actions/publish', params=parameters, headers=headers)
        if not response.ok:
            raise Exception(f'Falha na chamada: publish_flow_by_id({parameters=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('PublishResponse', response.json())
        data = class_new()
        return data

    def update_flow_by_id(self, flow_id: str) -> tuple[bool, None|str]:
        try:
            flow = self.get_flow_by_id(flow_id)

            success, error = True, None
            dados = api.checkout_flow_by_id(flow_id)
            print(f'{flow.name} - id:',dados.currentOperation.id)
            print(f'{flow.name} - action name:',dados.currentOperation.actionName)
            print(f'{flow.name} - action status:',dados.currentOperation.actionStatus)

            dados = api.checkin_flow_by_id(flow_id)
            print(flow.name, dados)
            dados = api.get_flow_by_id(flow_id)
            print(f'{flow.name} - id:',dados.currentOperation.id)
            print(f'{flow.name} - action name:',dados.currentOperation.actionName)
            print(f'{flow.name} - action status:',dados.currentOperation.actionStatus)

            dados = api.publish_flow_by_id(flow_id)
            print(flow.name,dados)
            dados = api.get_flow_by_id(flow_id)
            print(f'{flow.name} - id:',dados.currentOperation.id)
            print(f'{flow.name} - action name:',dados.currentOperation.actionName)
            print(f'{flow.name} - action status:',dados.currentOperation.actionStatus)
        except Exception as erro:
            success, error = False, erro
        finally:
            return success, error     

    def get_last_configuration_flow_by_id(self, flow_id: str) -> object:
        """
        GET /api/v2/flows/{flowId}/latestConfiguration HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/{flow_id}/latestConfiguration', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Falha na chamada: get_last_configuration_flow_by_id({flow_id=})\nstatus_code: {response.status_code}\ntext: {response.text}\n')
        class_new = json_for_class('ConfigurationFlow', response.json())
        data = class_new()
        return data

    def get_dependencies(self, flow_id: str, flows: list = []) -> list:
        flows = [flow_id]
        dados = api.get_last_configuration_flow_by_id(flow_id)
        for flow in dados.manifest.inboundCallFlow:
            if flow.id in flows:
                continue
            print(flow.name)
            flows.extend(self.get_dependencies(flow.id, flows))
        return list(set(flows))
    
if __name__ == "__main__":
    print('Carregando API...')
    api = Genesys('VIA')
    print('Vamos começar:')
    #flow_name = 'HML_IVR_ClubeSaude_v32_Modulo1_Fluxo_Inicial'
    #flow = api.get_flow_by_name(flow_name)
    flow_id = '08bb8ff6-242d-4bb5-98ad-3d9d32aa019f'
    print(api.update_flow_by_id(flow_id))
    
