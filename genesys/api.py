import requests
import base64
import os
import json
from dotenv import load_dotenv
import time
import re

load_dotenv()

class Genesys:
    ALLOWED_REGION_SUFFIXES = {
        # North America
        "mypurecloud.com",          # US (domínio legado/alternativo)
        "use1.pure.cloud",          # US East
        "usw2.pure.cloud",          # US West
        "use2.us-gov-pure.cloud",   # FedRAMP
        "cac1.pure.cloud",          # Canada
        "mxc1.pure.cloud",          # Mexico

        # South America
        "sae1.pure.cloud",          # São Paulo

        # Asia Pacific
        "apse2.pure.cloud",         # Sydney
        "mypurecloud.com.au",       # Sydney (alternativo)
        "apne1.pure.cloud",         # Tokyo
        "mypurecloud.jp",           # Tokyo (alternativo)
        "apne2.pure.cloud",         # Seoul
        "aps1.pure.cloud",          # Mumbai
        "apne3.pure.cloud",         # Osaka
        "apse1.pure.cloud",         # Singapore

        # Satellite media regions (listadas como satélite na doc)
        "ape1.pure.cloud",          # Hong Kong (satélite)
        "apse3.pure.cloud",         # Jakarta (satélite)

        # EMEA
        "euw1.pure.cloud",          # Ireland
        "mypurecloud.ie",           # Ireland (alternativo)
        "euc1.pure.cloud",          # Frankfurt
        "mypurecloud.de",           # Frankfurt (alternativo)
        "euw2.pure.cloud",          # London
        "euc2.pure.cloud",          # Zurich
        "mec1.pure.cloud",          # UAE

        # Satellite media regions (EMEA)
        "afs1.pure.cloud",          # Cape Town (satélite)
        "euw3.pure.cloud",          # Paris (satélite)
    }

    def normalize_region(self, region: str) -> str:
        region_lower = (region or "").strip().lower()

        # remove esquema, se vier URL completa
        r = region_lower.removeprefix("https://").removeprefix("http://")

        # remove caminhos, se existirem
        r = r.split("/", 1)[0]

        # remove prefixos comuns (api/login/apps/journey-websockets)
        for prefix in ("api.", "login.", "apps.", "journey-websockets."):
            if r.startswith(prefix):
                r = r[len(prefix):]
                break

        if r not in self.ALLOWED_REGION_SUFFIXES:
            raise ValueError(f"Region inválida: {region}. Permitidas: {sorted(self.ALLOWED_REGION_SUFFIXES)}")

        return r

    def __init__(self, client_id: str, client_secret: str, region: str) -> None:
        region_suffix = self.normalize_region(region)
        self.URL_AUTH = f"https://login.{region_suffix}"
        self.URL = f"https://api.{region_suffix}"
        self.CLIENT_ID = client_id
        self.CLIENT_SECRET = client_secret
        self.token = self.get_token()
        
    def __new__(cls, *args):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Genesys, cls).__new__(cls)
        return cls.instance
    
    def _check_and_update_token(self):
        """
        client.credentials.token.rate.per.minute
        | The maximum number of requests per client
          credentials grant token per minute
        | 300\n
        org.app.user.rate.per.minute
        | The maximum number of requests per organization
          per OAuth client per user per minute
        | 3000\n
        request.bytes.max
        | The maximum content length of a request payload
        | 512000\n
        token.rate.per.minute
        | The maximum number of requests per token per minute
        | 300
        """
        if time.time() - self._last_reset_time >= 60:
            self._call_count = 0
            self._last_reset_time = time.time()

        if self._call_count >= 3000:
            print("Atingido o limite de chamadas. Aguarde um minuto...")
            time.sleep(60)
            self._call_count = 0
            self._last_reset_time = time.time()
            self.update_token()
        else:
            self._call_count += 1

    def get_token(self) -> str:
        authorization = base64.b64encode(bytes(self.CLIENT_ID + ":" + self.CLIENT_SECRET, "ISO-8859-1")).decode("ascii")

        request_headers = {
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        request_body = {
            "grant_type": "client_credentials"
        }

        response = requests.post(f"{self.URL_AUTH}/oauth/token", data=request_body, headers=request_headers)

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
        response = requests.head(url=f"{self.URL}/api/v2/tokens/me", headers=headers)
        if response.status_code != 200:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')
        return None

    def check_token(self) -> None:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.head(url=f'{self.URL}/api/v2/tokens/me', headers=headers)
        if not response.ok:
            raise Exception(f'Token Genesys inválido, failure: {response.status_code} - {response.reason}')

    def get_conversation_by_id(self, conversation_id: str) -> dict:
        """
        GET /api/v2/conversations/{conversationId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}"
        }
        response = requests.get(url=f'{self.URL}/api/v2/conversations/{conversation_id}', headers=headers)
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_conversation_by_id({conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_conversations_details_by_query(self, body: dict) -> dict:
        """
        POST /api/v2/analytics/conversations/details/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/analytics/conversations/details/query",
            headers=headers,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_conversations_details_by_query({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def update_attributes_by_conversationId_and_participantId(
        self, conversation_id: str, participant_id: str, body: dict
    ) -> dict:
        """
        PATCH
        /api/v2/conversations/{conversationId}/participants/{participantId}/attributes\n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        payload = json.dumps(body)
        url = (
            f"{self.URL}/api/v2/conversations/{conversation_id}"
            f"/participants/{participant_id}/attributes"
        )
        response = requests.patch(
            url=url,
            headers=headers,
            data=payload,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{conversation_id=},{participant_id=},{payload=}"
            erro = f"update_attributes_by_conversationId_and_participantId({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def get_user_prompt_by_name_or_description(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> dict:
        """
        GET /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_user_prompt_by_name_or_description"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/prompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_user_prompts(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> dict:
        """
        GET /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_user_prompts"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/prompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_system_prompts(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> dict:
        """
        GET /api/v2/architect/systemprompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_system_prompts"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/systemprompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_system_prompt_by_name_or_description(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> dict:
        """
        GET /api/v2/architect/systemprompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_system_prompt_by_name_or_description"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": name,
            "description": description,
            "nameOrDescription": name_or_description,
            "includeMediaUris": True,
            "includeResources": True,
            "language": language,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/systemprompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def get_data_table_by_name(
        self,
        name: str,
        page_number: int = 1,
        page_size: int = 50,
        expand: str = "",
    ) -> dict:
        """
        GET /api/v2/flows/datatables/divisionviews HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_data_table_by_name"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_data_tables(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: str = "",
        expand: str = "",
    ) -> dict:
        """
        GET /api/v2/flows/datatables/divisionviews HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_data_tables"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_row_data_table_by_id(
        self,
        data_table_id: str,
        row_id: str,
    ) -> dict:
        """
        GET /api/v2/flows/datatables/{datatableId}/rows/{rowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_row_data_table_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {"showbrief": True}
        url = f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows/{row_id}"
        response = requests.get(
            url=url,
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{data_table_id=}, {row_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_data_action_by_name(
        self,
        category_name: str,
        name_data_action: str,
        page_number: int = 1,
        page_size: int = 50,
    ) -> dict:
        """
        GET /api/v2/integrations/actions HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_data_action_by_name"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "category": category_name,
            "name": name_data_action,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/integrations/actions",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def test_data_action(
        self, data_action_id: str, body: dict, tempo_timeout: int = 60
    ) -> tuple[dict, str]:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "teste_data_action"
        response = None
        try:
            status = ""
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.token}",
            }
            response = requests.post(
                url=f"{self.URL}/api/v2/integrations/actions/{data_action_id}/test",
                headers=headers,
                data=json.dumps(body),
                timeout=tempo_timeout,
            )
            status = response.status_code
            if response.ok:
                return (response.json(), "success")
            elif status == 408 or status == 504:
                return (response.json(), "timeout")
            return (response.json(), "failure")
        except requests.exceptions.ReadTimeout:
            return ({}, "timeout")
        except Exception as erro:
            content = ""
            if response:
                content = f"\nContent: {response.content}"
            parameters = f"{data_action_id=}, {body=}, {tempo_timeout=}"
            erro = f"{name_function}({parameters}){content}\n{erro}"
            raise Exception(erro)

    def execute_data_action(
        self, data_action_id: str, body: dict, tempo_timeout: int = 60
    ) -> tuple[dict, str]:
        """
        GET /api/v2/integrations/actions/{actionId}/execute \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "execute_data_action"
        response = None
        try:
            status = ""
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.token}",
            }
            response = requests.post(
                url=f"{self.URL}/api/v2/integrations/actions/{data_action_id}/execute",
                headers=headers,
                data=json.dumps(body),
                timeout=tempo_timeout,
            )
            status = response.status_code
            if response.ok:
                return (response.json(), "success")
            elif status == 408 or status == 504:
                return (response.json(), "timeout")
            return (response.json(), "failure")
        except requests.exceptions.ReadTimeout:
            return ({}, "timeout")
        except Exception as erro:
            content = ""
            if response:
                content = f"\nContent: {response.content}"
            parameters = f"{data_action_id=}, {body=}, {tempo_timeout=}"
            erro = f"{name_function}({parameters}){content}\n{erro}"
            raise Exception(erro)
            
    def get_ivr_by_id(self, ivr_id: str) -> dict:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_ivr_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/ivrs/{ivr_id}",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{ivr_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def get_ivrs(
        self,
        name: str = "",
        dnis: str = "",
        schedule_group: str = "",
        page_number: int = 1,
        page_size: int = 50,
    ) -> dict:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_ivrs"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "sortBy": "name",
            "sortOrder": "asc",
            "name": name,
            "dnis": dnis,
            "scheduleGroup": schedule_group,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/ivrs",
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_did_pool_by_number(self, number_match: str) -> dict:
        """
        GET /api/v2/telephony/providers/edges/didpools/dids HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_did_pool_by_number"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "numberMatch": number_match,
            "type": "ASSIGNED_AND_UNASSIGNED",
        }
        url = f"{self.URL}/api/v2/telephony/providers/edges/didpools/dids"
        response = requests.get(
            url=url,
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_flow_by_id(self, flow_id: str) -> dict:
        """
        GET /api/v2/flows/{flowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_flow_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/{flow_id}", headers=headers
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{flow_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def get_flows(
        self,
        flow_name_or_description: str,
        page_number: int = 1,
        page_size: int = 50,
        type_flow: str = "inboundcall",
    ) -> dict:
        """
        GET /api/v2/flows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_flows"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "sortBy": "name",
            "sortOrder": "asc",
            "includeSchemas": "true",
            "nameOrDescription": f"*{flow_name_or_description}*",
            "type": type_flow,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows",
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()

    def get_flow_by_name(
        self, flow_name: str, page_number: int = 1, page_size: int = 50
    ) -> dict:
        """
        GET /api/v2/flows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_flow_by_name"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": flow_name,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows",
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()
    
    def create_new_user_prompt(self, name: str, description: str) -> dict:
        """
        POST /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "create_new_user_prompt"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        body = {"name": name, "description": description}
        response = requests.post(
            url=f"{self.URL}/api/v2/architect/prompts",
            headers=headers,
            data=json.dumps(body),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()

    def create_new_user_prompt_resource(
        self, prompt_id: str, language: str, ttsString: str, text: str
    ) -> dict:
        """
        POST /api/v2/architect/prompts/{promptId}/resources HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "create_new_user_prompt_resource"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        body = {"language": language, "ttsString": ttsString, "text": text}
        url = f"{self.URL}/api/v2/architect/prompts/{prompt_id}/resources"
        response = requests.post(
            url=url,
            headers=headers,
            data=json.dumps(body),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()

    def get_version_last_flow_by_name(self, flow_name: str) -> int:
        fluxos = []
        page_number = 1
        regex = r"_(?:V|v)(\d+)_"
        while True:
            dados = self.get_flows(
                flow_name_or_description=flow_name, page_number=page_number
            )
            if len(fluxos) >= dados.get("total", 0):
                break
            for fluxo in dados["entities"]:
                fluxos.extend([re.search(regex, fluxo.name)])
            page_number += 1
        return max([int(match.group(1)) for match in fluxos])

    def upload_user_prompt_resource_by_url(
        self, upload_url: str, file_name: str, file_path: str
    ) -> dict:
        """
        Upload file a user prompt resource

        POST upload_url HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "upload_user_prompt_resource_by_url"
        response = None
        try:
            headers = {"Authorization": f"bearer {self.token}"}
            wav_form_data = {"file": (file_name, open(file_path, "rb"))}

            response = requests.post(
                upload_url,
                files=wav_form_data,
                headers=headers,
            )
            if not response.ok:
                content = f"\nContent: {response.content}\n"
                parameters = f"{upload_url=}, {file_name=}, {file_path=}"
                erro = f"{name_function}({parameters}){content}"
                raise Exception(erro)
            return response.json()
        except Exception as error:
            content = ""
            if response:
                content = f"\nContent: {response.content}"
            parameters = f"{upload_url=}, {file_name=}, {file_path=}"
            erro = f"{name_function}({parameters}){content}\n{error}"
            raise Exception(erro)

    def get_user_by_name(
        self, user_name: str, page_number: int = 1, page_size: int = 20
    ) -> dict:
        """
        POST /api/v2/users/search HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_user_by_name"
        body = {
            "pageSize": page_size,
            "pageNumber": page_number,
            "query": [
                {
                    "type": "EXACT",
                    "fields": ["state"],
                    "values": ["active", "inactive"],
                },
                {
                    "type": "QUERY_STRING",
                    "fields": ["name"],
                    "value": user_name,
                },
            ],
            "sortOrder": "ASC",
            "sortBy": "name",
            "expand": ["authorization", "team"],
            "enforcePermissions": True,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/users/search",
            data=json.dumps(body),
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()

    def get_user_by_email(
        self, user_email: str, page_number: int = 1, page_size: int = 20
    ) -> dict:
        """
        POST /api/v2/users/search HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_user_by_email"
        body = {
            "pageSize": page_size,
            "pageNumber": page_number,
            "query": [
                {
                    "type": "EXACT",
                    "fields": ["state"],
                    "values": ["active", "inactive"],
                },
                {
                    "type": "QUERY_STRING",
                    "fields": ["email"],
                    "value": user_email,
                },
            ],
            "sortOrder": "ASC",
            "sortBy": "name",
            "expand": ["images", "authorization", "team"],
            "enforcePermissions": True,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/users/search",
            data=json.dumps(body),
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()

    def set_new_password_for_user_by_user_id(
        self, user_id: str, new_password: str
    ) -> None:
        """
        POST /api/v2/users/{userId}/password HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "set_new_password_for_user_by_user_id"
        body = {"newPassword": new_password}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/users/{user_id}/password",
            data=json.dumps(body),
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{user_id=}, {new_password=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)

    def get_recipients_routing(
        self, page_number: int = 1, page_size: int = 20
    ) -> dict:
        """
        GET /api/v2/routing/message/recipients HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_recipients_routing"
        parameters = {"pageNumber": page_number, "pageSize": page_size}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/message/recipients",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def search_flow_prd_by_name_or_id(self, flow_name_or_id: str) -> bool:
        ivr_objects = self.get_ivrs()
        for ivr in ivr_objects["entities"]:
            flow_id = ivr["openHoursFlow"]["id"]
            flow_name = ivr["openHoursFlow"]["name"]
            if flow_name_or_id in (flow_id, flow_name):
                return True

        ivr_objects = self.get_recipients_routing()
        for ivr in ivr_objects["entities"]:
            flow_id = ivr["flow"]["id"]
            flow_name = ivr["flow"]["name"]
            if flow_name_or_id in (flow_id, flow_name):
                return True
        return False

    def checkin_flow_by_id(self, flow_id: str) -> dict:
        """
        POST /api/v2/flows/actions/checkin HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "checkin_flow_by_id"
        parameters = {"flow": flow_id}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/checkin",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def checkout_flow_by_id(self, flow_id: str) -> dict:
        """
        POST /api/v2/flows/actions/checkout HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "checkout_flow_by_id"
        parameters = {"flow": flow_id}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/checkout",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def publish_flow_by_id(self, flow_id: str) -> dict:
        """
        POST /api/v2/flows/actions/publish HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "publish_flow_by_id"
        parameters = {"flow": flow_id}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/publish",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def update_flow_by_id(self, flow_id: str) -> tuple[bool, None | str]:
        success, error = False, None
        try:
            flow = self.get_flow_by_id(flow_id)

            dados = self.checkout_flow_by_id(flow_id)
            current_operation = dados["currentOperation"]
            print(f"{flow["name"]} - id: {current_operation["id"]}")
            print(f"{flow["name"]} - action name: {current_operation["actionName"]}")
            status = current_operation["actionStatus"]
            print(f"{flow["name"]} - action status: {status}")

            dados = self.checkin_flow_by_id(flow_id)
            print(flow["name"], dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados["currentOperation"]
            print(f"{flow["name"]} - id: {current_operation["id"]}")
            print(f"{flow["name"]} - action name: {current_operation["actionName"]}")
            status = current_operation["actionStatus"]
            print(f"{flow["name"]} - action status: {status}")

            dados = self.publish_flow_by_id(flow_id)
            print(flow["name"], dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados["currentOperation"]
            print(f"{flow["name"]} - id: {current_operation["id"]}")
            print(f"{flow["name"]} - action name: {current_operation["actionName"]}")
            status = current_operation["actionStatus"]
            print(f"{flow["name"]} - action status: {status}")
            success, error = True, None
        except Exception as erro:
            success, error = False, str(error)
        finally:
            return success, error

    def get_last_configuration_flow_by_id(self, flow_id: str) -> dict:
        """
        GET /api/v2/flows/{flowId}/latestConfiguration HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_last_configuration_flow_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        url = f"{self.URL}/api/v2/flows/{flow_id}/latestConfiguration"
        response = requests.get(
            url=url,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{flow_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def get_dependencies(self, flow_id: str, flows: list = []) -> list:
        flows = [flow_id]
        dados = self.get_last_configuration_flow_by_id(flow_id)
        for flow in dados["manifest"]["inboundCallFlow"]:
            if flow["id"] in flows:
                continue
            print(flow["name"])
            flows.extend(self.get_dependencies(flow["id"], flows))
        return list(set(flows))

    def search_flow_is_prd(self, flow_name_or_id: str) -> bool:
        ivr_objects = self.get_ivrs(page_size=200)
        for ivr in ivr_objects["entities"]:
            flow_id = ivr["openHoursFlow"]["id"]
            flow_name = ivr["openHoursFlow"]["name"]
            if flow_name_or_id in (flow_id, flow_name):
                return True
            dados = self.get_last_configuration_flow_by_id(flow_id)

            if hasattr(dados["manifest"], "inboundCallFlow"):
                for flow in dados["manifest"]["inboundCallFlow"]:
                    flow_id = flow.id
                    flow_name = flow.name
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

        receipe_objects = self.get_recipients_routing(page_size=200)
        for receipe in receipe_objects["entities"]:
            flow_id = receipe["flow"]["id"]
            flow_name = receipe["flow"]["name"]
            if flow_name_or_id in (flow_id, flow_name):
                return True
            dados = self.get_last_configuration_flow_by_id(flow_id)

            if hasattr(dados["manifest"], "commonModuleFlow"):
                for flow in dados["manifest"]["commonModuleFlow"]:
                    flow_id = flow["id"]
                    flow_name = flow["name"]
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

            if hasattr(dados["manifest"], "botFlow"):
                for flow in dados["manifest"]["botFlow"]:
                    flow_id = flow["id"]
                    flow_name = flow["name"]
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

        return False

    def get_execution_by_id(self, execution_id: str) -> dict:
        """
        GET /api/v2/flows/executions/{executionId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_execution_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/executions/{execution_id}",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({execution_id=}){content}"
            raise Exception(erro)
        return response.json()

    def run_execution(self, body: dict) -> dict:
        """
        POST /api/v2/flows/executions \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "run_execution"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/executions",
            headers=headers,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()

    def get_gamification_scorecards_by_user(self, user_id: str, workday: str) -> dict:
        """
        GET /api/v2/gamification/scorecards/users/{userId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_gamification_scorecards_by_user"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/scorecards/users/{user_id}?workday={workday}&expand=objective",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({user_id=}, {workday=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_gamification_profile_by_user(self, user_id: str, workday: str) -> dict:
        """
        GET /api/v2/gamification/profiles/users/{userId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_gamification_profile_by_user"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/profiles/users/{user_id}?workday={workday}",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({user_id=}, {workday=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_gamification_metric_by_profile(self, profile_id: str, metric_id: str) -> dict:
        """
        GET /api/v2/gamification/profiles/{profileId}/metric/{metricId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_gamification_metric_by_profile"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/profiles/{profile_id}/metrics/{metric_id}",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({profile_id=}, {metric_id=}){content}"
            raise Exception(erro)
        return response.json()

