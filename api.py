import requests
import base64
import os
import json
from dotenv import load_dotenv

load_dotenv()

class Genesys:
    DADOS = json.loads(os.environ.get('DADOS'))

    def __init__(self, org: str) -> None:
        if org not in self.DADOS.keys():
            raise ValueError('Organização Desconhecida')
        self.URL_AUTH = self.DADOS[org]['URL_AUTH']
        self.URL = self.DADOS[org]['URL']
        self.CLIENT_ID = self.DADOS[org]['CLIENT_ID']
        self.CLIENT_SECRET = self.DADOS[org]['CLIENT_SECRET']
        self.token = self.get_token()
        #self.update_token()
        

    def __new__(self, *args):
        if not hasattr(self, 'instance'):
            self.instance = super(Genesys, self).__new__(self)
        return self.instance

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

    def get_conversation_call(self, conversation_id: str) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/conversations/calls/{conversation_id}', headers=headers)
        dados = result.json()
        if not result.ok:
            raise Exception(f'Falha na chamada(get_conversation_call({conversation_id=})), status: {result.status_code}, json: {dados}')
        return dados

    def get_prompt(self, name_prompt: str, language: str = 'pt-br'):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/architect/prompts?name={name_prompt}', headers=headers)
        dados = result.json()
        if not result.ok:
            raise Exception(f'Falha na chamada(procurar_prompt({name_prompt})), status: {result.status_code}, json: {dados}')
        if dados['total'] != 1:
            return {'prompt-name':name_prompt}
        entitie = dados['entities'][0]
        description = entitie['description']
        tts = None
        media_uri = None
        for prompt in entitie['resources']:
            if prompt.get('language') == language:
                tts = prompt.get('ttsString')
                media_uri = prompt.get('mediaUri')
                break
        return {
            'prompt-name': name_prompt,
            'prompt-description': description,
            'prompt-url': media_uri,
            'prompt-tts': tts
        }
    
    def get_prompt_system(self, name_prompt: str, language: str = 'pt-br'):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/architect/systemprompts?name={name_prompt}', headers=headers)
        dados = result.json()
        if not result.ok:
            raise Exception(f'Falha na chamada(procurar_prompt({name_prompt})), status: {result.status_code}, json: {dados}')
        if dados['total'] != 1:
            return {'prompt-name':name_prompt}
        entitie = dados['entities'][0]
        description = entitie['description']
        tts = None
        media_uri = None
        for prompt in entitie['resources']:
            if prompt.get('language') == language:
                tts = prompt.get('ttsString')
                media_uri = prompt.get('mediaUri')
                break
        return {
            'prompt-name': name_prompt,
            'prompt-description': description,
            'prompt-url': media_uri,
            'prompt-tts': tts
        }

    def get_data_table(self, name_data_table: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/flows/datatables/divisionviews?name={name_data_table}', headers=headers)
        dados = result.json()
        if not result.ok:
            raise Exception(f'Falha na chamada(procurar_data_table({name_data_table})), status: {result.status_code}, json: {dados}')
        if dados['total'] != 1:
            raise Exception(f'Falha na chamada(procurar_data_table({name_data_table})), status: {result.status_code}, json: {dados}')
        return dados['entities'][0]['id']
    
    def get_row_data_table(self, data_table_id: str, key: str) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/flows/datatables/{data_table_id}/rows/{key}?showbrief=false', headers=headers)
        dados = result.json()
        if result.status_code != 200 and result.status_code != 404:
            raise Exception(f'Falha na chamada(procurar_row_data_table({data_table_id}, {key})), status: {result.status_code}, json: {dados}')
        return dados
    
    def get_data_action(self, category_name: str, name_data_action: str) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        result = requests.get(url='https://'+self.URL+f'/api/v2/integrations/actions?category={category_name}&name={name_data_action}', headers=headers)
        dados = result.json()
        if result.status_code != 200 and len(dados['entities']) == 0:
            raise Exception(f'Falha na chamada(procurar_data_action({category_name}, {name_data_action})), status: {result.status_code}, json: {dados}')
        return dados['entities'][0]

    def execute_data_action(self, data_action_id: str, body: dict, tempo_timeout: int) -> tuple[dict, str]:
        status = ''
        dados = ''
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.token}"
            }
            result = requests.post(url='https://'+self.URL+f'/api/v2/integrations/actions/{data_action_id}/test', headers=headers, data=json.dumps(body), timeout=tempo_timeout)
            status = result.status_code
            dados = result.json()
            if result.ok:
                return (dados, 'success')
            elif status == 408 or status == 504:
                return (dados, 'timeout')
            return (dados, 'failure')
        except requests.exceptions.ReadTimeout:
            return ({},'timeout')
        except Exception as erro:
            raise Exception(f'Falha na chamada(executar_data_action({data_action_id}), status: {status}, json: {dados}, erro: {erro}')

    def get_ivr(self, ivr_id) -> dict:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/architect/ivrs/{ivr_id}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return response.json()
    
    def get_did_pool(self, number_match: str) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/telephony/providers/edges/didpools/dids?type=ASSIGNED_AND_UNASSIGNED&numberMatch={number_match}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return response.json()
    
    def get_flow_id(self, flow_id) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows/{flow_id}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return response.json()
    
    def get_flows(self, flow_name_or_description: str, page_number: int = 1, page_size: int = 50, type_flow: str = 'inboundcall') -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows?includeSchemas=true&nameOrDescription=*{flow_name_or_description}*&sortBy=name&sortOrder=asc&pageNumber={page_number}&pageSize={page_size}&type={type_flow}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return response.json()
    
    def get_flow_name(self, flow_name) -> str:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url='https://'+self.URL+f'/api/v2/flows?pageSize=1&name={flow_name}', headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return response.json()['entities']
    
    def create_new_user_prompt(self, name: str, description: str) -> dict:
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
            raise Exception(f'Falha em criar prompt, failure: {response.status_code} - {response.reason}')
        return response.json()
    
    def create_new_user_prompt_resource(self, prompt_id: str, language: str, ttsString: str, text: str) -> dict:
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
            raise Exception(f'Falha em criar recurso de prompt, failure: {response.status_code} - {response.reason}')
        return response.json()

if __name__ == '__main__':
    api = Genesys()