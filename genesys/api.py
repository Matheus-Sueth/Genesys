import requests
import os
import json
import re
import time
import base64
from dotenv import dotenv_values


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
                    name_sub_classe = f"{key[:-1].capitalize()}_{index}"
                    sub_classe = type(name_sub_classe, (), {})
                    getattr(classe, key).append(sub_classe)
                    def_attribute(item, sub_classe)

        else:
            setattr(classe, key, value)


def json_for_class(class_name: str, dict_data: dict) -> object:
    class_new = type(class_name, (), {})

    def __str__(self):
        atributos = [f"{key}: {value}" for key, value in dict_data.items()]
        return f"{class_name}({", ".join(atributos)})"

    def_attribute(dict_data, class_new)
    setattr(class_new, "__str__", __str__)
    return class_new


vars_dotenv = dotenv_values(os.environ.get("DADOS"))


class Genesys:
    DADOS = json.loads(vars_dotenv.get("DADOS"))

    def __init__(self, org: str) -> None:
        self.org = org
        if org not in self.DADOS.keys():
            raise ValueError("Organização Desconhecida")
        self.URL = self.DADOS[org]["URL"]
        self.URL_AUTH = self.DADOS[org]["URL_AUTH"]
        self.CLIENT_ID = self.DADOS[org]["CLIENT_ID"]
        self.CLIENT_SECRET = self.DADOS[org]["CLIENT_SECRET"]
        self.token = self.get_token()

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
            self._update_apis()
        else:
            self._call_count += 1

    def __new__(self, *args):
        if not hasattr(self, "instance"):
            self.instance = super(Genesys, self).__new__(self)
        return self.instance

    def __str__(self):
        return f"APIs Genesys PureCloud utilizando o ambiente: {self.org}"

    def get_token(self) -> str:
        name_function = "get_token"
        authorization = base64.b64encode(
            bytes(self.CLIENT_ID + ":" + self.CLIENT_SECRET, "ISO-8859-1")
        ).decode("ascii")

        request_headers = {
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        request_body = {"grant_type": "client_credentials"}

        response = requests.post(
            f"https://login.{self.URL_AUTH}/oauth/token",
            data=request_body,
            headers=request_headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({self.org}){content}"
            raise Exception(erro)

        response_json = response.json()
        return response_json["access_token"]

    def update_token(self) -> None:
        name_function = "update_token"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.head(
            url=f"https://{self.URL}/api/v2/tokens/me", headers=headers
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({self.org}){content}"
            raise Exception(erro)

    def check_token(self) -> None:
        name_function = "check_token"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.head(
            url=f"https://{self.URL}/api/v2/tokens/me", headers=headers
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({self.org}){content}"
            raise Exception(erro)

    def get_conversation_by_id(self, conversation_id: str) -> object:
        """
        GET /api/v2/conversations/{conversationId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_conversation_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.get(
            url=f"https://{self.URL}/api/v2/conversations/{conversation_id}",
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({conversation_id=}){content}"
            raise Exception(erro)

        class_new = json_for_class("Conversation", response.json())
        data = class_new()
        return data

    def update_attributes_by_conversationId_and_participantId(
        self, conversation_id: str, participant_id: str, body: dict
    ) -> object:
        """
        PATCH
        /api/v2/conversations/{conversationId}/participants/{participantId}/attributes\n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "update_attributes_by_conversationId_and_participantId"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        payload = json.dumps(body)
        url = (
            f"https://{self.URL}/api/v2/conversations/{conversation_id}"
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
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("Attributes", response.json())
        data = class_new()
        return data

    def get_conversation_call_by_id(self, conversation_id: str) -> object:
        """
        GET /api/v2/conversations/calls/{conversationId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_conversation_call_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        rota = f"/api/v2/conversations/calls/{conversation_id}"
        url = f"https://{self.URL}{rota}"
        response = requests.get(
            url=url,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{conversation_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("CallConversation", response.json())
        data = class_new()
        return data

    def get_user_prompt_by_name_or_description(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/prompts",
            params=parameters,
            headers=headers,
        )
        dados = response.json()
        if not response.ok or dados["total"] != 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("UserPrompt", dados["entities"][0])
        data = class_new()
        return data

    def get_user_prompts(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/prompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("UserPrompts", response.json())
        data = class_new()
        return data

    def get_system_prompts(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/systemprompts",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("SystemPrompts", response.json())
        data = class_new()
        return data

    def get_system_prompt_by_name_or_description(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: list[str] = [""],
        description: str = "",
        name_or_description: str = "",
        language: list[str] = ["pt-br"],
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/systemprompts",
            params=parameters,
            headers=headers,
        )
        dados = response.json()
        if not response.ok or dados["total"] != 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("SystemPrompts", dados["entities"][0])
        data = class_new()
        return data

    def get_data_table_by_name(
        self,
        name: str,
        page_number: int = 1,
        page_size: int = 50,
        expand: str = "",
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=headers,
        )
        dados = response.json()
        if not response.ok or dados["total"] != 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("DataTable", dados["entities"][0])
        data = class_new()
        return data

    def get_data_tables(
        self,
        page_number: int = 1,
        page_size: int = 50,
        name: str = "",
        expand: str = "",
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("DataTables", response.json())
        data = class_new()
        return data

    def get_row_data_table_by_id(
        self,
        data_table_id: str,
        row_id: str,
    ) -> object:
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
        rota = f"/api/v2/flows/datatables/{data_table_id}/rows/{row_id}"
        url = f"https://{self.URL}{rota}"
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
        class_new = json_for_class("RowDataTable", response.json())
        data = class_new()
        return data

    def get_data_action_by_name(
        self,
        category_name: str,
        name_data_action: str,
        page_number: int = 1,
        page_size: int = 50,
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/integrations/actions",
            params=parameters,
            headers=headers,
        )
        dados = response.json()
        if not response.ok and len(dados["entities"]) != 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("DataAction", dados["entities"][0])
        data = class_new()
        return data

    def execute_data_action(
        self, data_action_id: str, body: dict, tempo_timeout: int = 60
    ) -> tuple[dict, str]:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "execute_data_action"
        try:
            status = ""
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.token}",
            }
            response = requests.post(
                url="https://"
                + self.URL
                + f"/api/v2/integrations/actions/{data_action_id}/test",
                headers=headers,
                data=json.dumps(body),
                timeout=tempo_timeout,
            )
            status = response.status_code
            data_action_name = f"custom_{data_action_id}"
            class_new = json_for_class(data_action_name, response.json())
            dados = class_new()
            if response.ok:
                return (dados, "success")
            elif status == 408 or status == 504:
                return (dados, "timeout")
            return (dados, "failure")
        except requests.exceptions.ReadTimeout:
            return ({}, "timeout")
        except Exception as erro:
            if not response.ok:
                content = f"\nContent: {response.content}\n"
                parameters = f"{data_action_id=}, {body=}, {tempo_timeout=}"
                erro = f"{name_function}({parameters}){content}\n{erro}"
                raise Exception(erro)

    def get_ivr_by_id(self, ivr_id: str) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/ivrs/{ivr_id}",
            headers=headers,
        )
        dados = response.json()
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{ivr_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("Ivr", dados)
        data = class_new()
        return data

    def get_ivrs(
        self,
        name: str = "",
        dnis: str = "",
        schedule_group: str = "",
        page_number: int = 1,
        page_size: int = 50,
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/ivrs",
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("Ivrs", response.json())
        data = class_new()
        return data

    def get_did_pool_by_number(self, number_match: str) -> object:
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
        rota = "/api/v2/telephony/providers/edges/didpools/dids"
        url = f"https://{self.URL}{rota}"
        response = requests.get(
            url=url,
            headers=headers,
            params=parameters,
        )
        dados = response.json()
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("DidPool", dados["entities"][0])
        data = class_new()
        return data

    def get_flow_by_id(self, flow_id: str) -> object:
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
            url=f"https://{self.URL}/api/v2/flows/{flow_id}", headers=headers
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{flow_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("Flow", response.json())
        data = class_new()
        return data

    def get_flows(
        self,
        flow_name_or_description: str,
        page_number: int = 1,
        page_size: int = 50,
        type_flow: str = "inboundcall",
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/flows",
            headers=headers,
            params=parameters,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("Flows", response.json())
        data = class_new()
        return data

    def get_flow_by_name(
        self, flow_name: str, page_number: int = 1, page_size: int = 50
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/flows",
            headers=headers,
            params=parameters,
        )
        dados = response.json()
        if not response.ok or dados["total"] != 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        class_new = json_for_class("Flow", dados["entities"][0])
        data = class_new()
        return data

    def create_new_user_prompt(self, name: str, description: str) -> object:
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
            url=f"https://{self.URL}/api/v2/architect/prompts",
            headers=headers,
            data=json.dumps(body),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        class_new = json_for_class("UserPrompt", response.json())
        data = class_new()
        return data

    def create_new_user_prompt_resource(
        self, prompt_id: str, language: str, ttsString: str, text: str
    ) -> object:
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
        rota = f"/api/v2/architect/prompts/{prompt_id}/resources"
        url = f"https://{self.URL}{rota}"
        response = requests.post(
            url=url,
            headers=headers,
            data=json.dumps(body),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        class_new = json_for_class("UserPromptResource", response.json())
        data = class_new()
        return data

    def get_version_last_flow_by_name(self, flow_name: str) -> int:
        fluxos = []
        page_number = 1
        regex = r"_(?:V|v)(\d+)_"
        while True:
            dados = self.get_flows(
                flow_name_or_description=flow_name, page_number=page_number
            )
            if len(fluxos) >= dados.total:
                break
            for fluxo in dados.entities:
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
            if not response.ok:
                content = f"\nContent: {response.content}\n"
                parameters = f"{upload_url=}, {file_name=}, {file_path=}"
                erro = f"{name_function}({parameters}){content}\n{error}"
                raise Exception(erro)

    def get_user_by_name(
        self, user_name: str, page_number: int = 1, page_size: int = 20
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/users/search",
            data=json.dumps(body),
            headers=headers,
        )
        dados = response.json()
        if not response.ok and len(dados["total"]) < 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        class_new = json_for_class("User", dados["results"])
        data = class_new()
        return data

    def get_user_by_email(
        self, user_email: str, page_number: int = 1, page_size: int = 20
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/users/search",
            data=json.dumps(body),
            headers=headers,
        )
        dados = response.json()
        if not response.ok and len(dados["total"]) < 1:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        class_new = json_for_class("User", dados["results"])
        data = class_new()
        return data

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
            url=f"https://{self.URL}/api/v2/users/{user_id}/password",
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
    ) -> object:
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
            url=f"https://{self.URL}/api/v2/routing/message/recipients",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("RecipientsMessage", response.json())
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
        name_function = "checkin_flow_by_id"
        parameters = {"flow": flow_id}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        response = requests.post(
            url=f"https://{self.URL}/api/v2/flows/actions/checkin",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("CheckinResponse", response.json())
        data = class_new()
        return data

    def checkout_flow_by_id(self, flow_id: str) -> object:
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
            url=f"https://{self.URL}/api/v2/flows/actions/checkout",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("Flow", response.json())
        data = class_new()
        return data

    def publish_flow_by_id(self, flow_id: str) -> object:
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
            url=f"https://{self.URL}/api/v2/flows/actions/publish",
            params=parameters,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("PublishResponse", response.json())
        data = class_new()
        return data

    def update_flow_by_id(self, flow_id: str) -> tuple[bool, None | str]:
        try:
            flow = self.get_flow_by_id(flow_id)

            success, error = True, None
            dados = self.checkout_flow_by_id(flow_id)
            current_operation = dados.currentOperation
            print(f"{flow.name} - id: {current_operation.id}")
            print(f"{flow.name} - action name: {current_operation.actionName}")
            status = current_operation.actionStatus
            print(f"{flow.name} - action status: {status}")

            dados = self.checkin_flow_by_id(flow_id)
            print(flow.name, dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados.currentOperation
            print(f"{flow.name} - id: {current_operation.id}")
            print(f"{flow.name} - action name: {current_operation.actionName}")
            status = current_operation.actionStatus
            print(f"{flow.name} - action status: {status}")

            dados = self.publish_flow_by_id(flow_id)
            print(flow.name, dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados.currentOperation
            print(f"{flow.name} - id: {current_operation.id}")
            print(f"{flow.name} - action name: {current_operation.actionName}")
            status = current_operation.actionStatus
            print(f"{flow.name} - action status: {status}")
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
        name_function = "get_last_configuration_flow_by_id"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {self.token}",
        }
        rota = f"/api/v2/flows/{flow_id}/latestConfiguration"
        url = f"https://{self.URL}{rota}"
        response = requests.get(
            url=url,
            headers=headers,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{flow_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        class_new = json_for_class("ConfigurationFlow", response.json())
        data = class_new()
        return data

    def get_dependencies(self, flow_id: str, flows: list = []) -> list:
        flows = [flow_id]
        dados = self.get_last_configuration_flow_by_id(flow_id)
        for flow in dados.manifest.inboundCallFlow:
            if flow.id in flows:
                continue
            print(flow.name)
            flows.extend(self.get_dependencies(flow.id, flows))
        return list(set(flows))

    def search_flow_is_prd(self, flow_name_or_id: str) -> bool:
        ivr_objects = self.get_ivrs(page_size=200)
        for ivr in ivr_objects.entities:
            flow_id = ivr.openHoursFlow.id
            flow_name = ivr.openHoursFlow.name
            if flow_name_or_id in (flow_id, flow_name):
                return True
            dados = self.get_last_configuration_flow_by_id(flow_id)

            if hasattr(dados.manifest, "inboundCallFlow"):
                for flow in dados.manifest.inboundCallFlow:
                    flow_id = flow.id
                    flow_name = flow.name
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

        receipe_objects = self.get_recipients_routing(page_size=200)
        for receipe in receipe_objects.entities:
            flow_id = receipe.flow.id
            flow_name = receipe.flow.name
            if flow_name_or_id in (flow_id, flow_name):
                return True
            dados = self.get_last_configuration_flow_by_id(flow_id)

            if hasattr(dados.manifest, "commonModuleFlow"):
                for flow in dados.manifest.commonModuleFlow:
                    flow_id = flow.id
                    flow_name = flow.name
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

            if hasattr(dados.manifest, "botFlow"):
                for flow in dados.manifest.botFlow:
                    flow_id = flow.id
                    flow_name = flow.name
                    if flow_name_or_id in (flow_id, flow_name):
                        return True

        return False
