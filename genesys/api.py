import requests
import base64
import os
import json
from dotenv import load_dotenv, dotenv_values
import time
import re
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Protocol, Optional, Dict, Any, Tuple

load_dotenv()


@dataclass(frozen=True)
class GenesysRegion:
    """Deriva URLs base a partir do sufixo (ex: sae1.pure.cloud)."""
    suffix: str

    @property
    def url_auth(self) -> str:
        return f"https://login.{self.suffix}"

    @property
    def url_api(self) -> str:
        return f"https://api.{self.suffix}"


class TokenProvider(Protocol):
    """Qualquer OAuth que você suportar precisa entregar um access token válido."""
    def get_access_token(self) -> str: ...
    def token_info(self) -> Dict[str, Any]: ...


@dataclass(frozen=True)
class ClientCredentialsKey:
    region_suffix: str
    client_id: str


class ClientCredentialsTokenProvider(TokenProvider):
    """
    Singleton por (region_suffix, client_id).
    Cacheia token e renova quando expira.
    """
    _instances: Dict[ClientCredentialsKey, "ClientCredentialsTokenProvider"] = {}

    def __new__(cls, key: ClientCredentialsKey, client_secret: str) -> "ClientCredentialsTokenProvider":
        if key not in cls._instances:
            inst = super().__new__(cls)
            cls._instances[key] = inst
        return cls._instances[key]

    def __init__(self, key: ClientCredentialsKey, client_secret: str) -> None:
        # __init__ pode ser chamado várias vezes no singleton
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.key = key
        self.client_secret = client_secret
        self.region = GenesysRegion(key.region_suffix)

        self._session = requests.Session()
        self._access_token: str = ""
        self._expires_at_epoch: int = 0
        self._raw: Dict[str, Any] = {}

    def get_access_token(self) -> str:
        now = int(time.time())
        if self._access_token and now < (self._expires_at_epoch - 30):
            return self._access_token

        token = self._request_token_client_credentials()
        self._raw = token

        self._access_token = token["access_token"]
        expires_in = int(token.get("expires_in", 0))
        self._expires_at_epoch = now + expires_in

        return self._access_token

    def token_info(self) -> Dict[str, Any]:
        info = dict(self._raw)
        info["type"] = "ClientCredentials"
        return info

    def _request_token_client_credentials(self) -> Dict[str, Any]:
        response = self._session.post(
            f"{self.region.url_auth}/oauth/token",
            data={"grant_type": "client_credentials"},
            auth=(self.key.client_id, self.client_secret),
            timeout=60,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"_request_token_client_credentials(){content}"
            raise Exception(erro)
        return response.json()


@dataclass(frozen=True)
class PkceConfig:
    region_suffix: str
    oauth_client_id: str
    redirect_uri: str


class PkceTokenProvider(TokenProvider):
    """
    Sem TokenStore por enquanto:
    - você injeta tokens (dict) após o callback
    - se expirar, você decide depois como refrescar/persistir
    """
    def __init__(self, cfg: PkceConfig, tokens: Optional[Dict[str, Any]] = None) -> None:
        self.cfg = cfg
        self.region = GenesysRegion(cfg.region_suffix)
        self._session = requests.Session()

        self._raw: Dict[str, Any] = {}
        self._access_token: Optional[str] = None
        self._expires_at_epoch: int = 0

        if tokens:
            self.set_tokens(tokens)

    def set_tokens(self, tokens: Dict[str, Any]) -> None:
        """
        Você chama isto no /auth/callback (depois do exchange code->token),
        ou quando carregar tokens de outro lugar no futuro.
        """
        now = int(time.time())
        self._raw = dict(tokens)

        self._access_token = tokens.get("access_token")
        expires_in = int(tokens.get("expires_in", 0))
        self._expires_at_epoch = now + expires_in

    def exchange_code_for_token(self, code: str, code_verifier: str) -> Dict[str, Any]:
        """
        Chamado no callback: troca authorization code por token e armazena em memória.
        """
        response = self._session.post(
            f"{self.region.url_auth}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.cfg.oauth_client_id,
                "redirect_uri": self.cfg.redirect_uri,
                "code": code,
                "code_verifier": code_verifier,
            },
            timeout=60,
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"exchange_code_for_token({code=}, {code_verifier=}){content}"
            raise Exception(erro)

        try:
            token = response.json()
            self.set_tokens(token)
            return token
        except ValueError:
            raise Exception(f"Resposta não-JSON em {response.url}: {response.text[:500]}")

    def get_access_token(self) -> str:
        if not self._access_token:
            raise RuntimeError("PKCE: access_token ausente. Complete login/callback antes de chamar APIs.")

        now = int(time.time())
        if now >= (self._expires_at_epoch - 30):
            # Sem store/refresh por enquanto — você decide depois.
            raise RuntimeError("PKCE: token expirado (refresh/persistência será implementado depois).")

        return self._access_token

    def token_info(self) -> Dict[str, Any]:
        info = dict(self._raw)
        info["type"] = "Pkce"
        return info
    

class Genesys:
    def __init__(self, region_suffix: str, token_provider: TokenProvider) -> None:
        self.region = GenesysRegion(region_suffix)
        self.URL_AUTH = self.region.url_auth
        self.URL = self.region.url_api
        self.token_provider = token_provider
        self.information_token = self.get_information_token()
        
    def __str__(self) -> str:
        return f"Genesys(org: {self.information_token['organization']['name']}, user: {self.information_token['OAuthClient']['name']})"
    
    def auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token_provider.get_access_token()}",
            "Content-Type": "application/json",
        }
    
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
        pass
    
    def delete_token_me(self) -> None:
        url = f"https://api.{self.URL}/api/v2/tokens/me"
        response = requests.delete(url, headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"delete_token_me(){content}"
            raise Exception(erro)

    def get_information_token(self) -> dict:
        response = requests.get(url=f'{self.URL}/api/v2/tokens/me', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_information_token(){content}"
            raise Exception(erro)
        return response.json()
    
    def get_user_by_token(self, expand: str = "routingStatus,presence,organization,dateLastLogin,integrationPresence,presence,routingskills,routinglanguages,token,groups") -> dict:
        """
        GET /api/v2/users/me \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/users/me?expand={expand}', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_user_by_token({expand=}){content}"
            raise Exception(erro)
        return response.json()

    def get_conversation_by_id(self, conversation_id: str) -> dict:
        """
        GET /api/v2/conversations/{conversationId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/conversations/{conversation_id}', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_conversation_by_id({conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_analytics_conversation_by_id(self, conversation_id: str) -> dict:
        """
        GET /api/v2/analytics/conversations/{conversationId}/details \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/analytics/conversations/{conversation_id}/details', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_analytics_conversation_by_id({conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_conversations_details_by_query(self, body: dict) -> dict:
        """
        POST /api/v2/analytics/conversations/details/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/analytics/conversations/details/query",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_conversations_details_by_query({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def create_channel_notifications(self) -> dict:
        """
        POST /api/v2/notifications/channels \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/notifications/channels",
            headers=self.auth_headers()
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"create_channel_notifications(){content}"
            raise Exception(erro)
        return response.json()
    
    def subscribe_topics_channel_notifications(self, channel_id: str, body: list[dict]) -> dict:
        """
        POST /api/v2/notifications/channels/{channelId}/subscriptions \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/notifications/channels/{channel_id}/subscriptions",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"subscribe_topics_channel_notifications({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_availabletopics_notifications(self) -> dict:
        """
        GET /api/v2/notifications/availabletopics \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/notifications/availabletopics', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_availabletopics_notifications(){content}"
            raise Exception(erro)
        return response.json()

    def get_channels_notifications(self) -> dict:
        """
        GET /api/v2/notifications/channels \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/notifications/channels', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_channels_notifications(){content}"
            raise Exception(erro)
        return response.json()
    
    def disconnect_interaction(self, conversation_id: str) -> dict:
        """
        POST /api/v2/conversations/{conversationId}/disconnect \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f'{self.URL}/api/v2/conversations/{conversation_id}/disconnect', 
            headers=self.auth_headers(),
            data=json.dumps({})
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"disconnect_interaction({conversation_id=}){content}"
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
        payload = json.dumps(body)
        url = (
            f"{self.URL}/api/v2/conversations/{conversation_id}"
            f"/participants/{participant_id}/attributes"
        )
        response = requests.patch(
            url=url,
            headers=self.auth_headers(),
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
            headers=self.auth_headers(),
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
            headers=self.auth_headers(),
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
            headers=self.auth_headers(),
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
            headers=self.auth_headers(),
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
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=self.auth_headers(),
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
        parameters = {
            "name": name,
            "pageNumber": page_number,
            "pageSize": page_size,
            "expand": expand,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/datatables/divisionviews",
            params=parameters,
            headers=self.auth_headers(),
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
        parameters = {"showbrief": True}
        url = f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows/{row_id}"
        response = requests.get(
            url=url,
            params=parameters,
            headers=self.auth_headers(),
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
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "category": category_name,
            "name": name_data_action,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/integrations/actions",
            params=parameters,
            headers=self.auth_headers(),
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
            response = requests.post(
                url=f"{self.URL}/api/v2/integrations/actions/{data_action_id}/test",
                headers=self.auth_headers(),
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
            response = requests.post(
                url=f"{self.URL}/api/v2/integrations/actions/{data_action_id}/execute",
                headers=self.auth_headers(),
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

    def get_metrics_dataactions(self, body: dict) -> dict:
        """
        POST /api/v2/analytics/actions/aggregates/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/analytics/actions/aggregates/query",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_metrics_dataactions({body=}){content}"
            raise Exception(erro)
        return response.json()
        
    def get_ivr_by_id(self, ivr_id: str) -> dict:
        """
        GET /api/v2/integrations/actions/{actionId}/test \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_ivr_by_id"
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/ivrs/{ivr_id}",
            headers=self.auth_headers(),
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
            headers=self.auth_headers(),
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
        parameters = {
            "numberMatch": number_match,
            "type": "ASSIGNED_AND_UNASSIGNED",
        }
        url = f"{self.URL}/api/v2/telephony/providers/edges/didpools/dids"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/{flow_id}", headers=self.auth_headers()
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
            headers=self.auth_headers(),
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
        parameters = {
            "pageNumber": page_number,
            "pageSize": page_size,
            "name": flow_name,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows",
            headers=self.auth_headers(),
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
        body = {"name": name, "description": description}
        response = requests.post(
            url=f"{self.URL}/api/v2/architect/prompts",
            headers=self.auth_headers(),
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
        body = {"language": language, "ttsString": ttsString, "text": text}
        url = f"{self.URL}/api/v2/architect/prompts/{prompt_id}/resources"
        response = requests.post(
            url=url,
            headers=self.auth_headers(),
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
            wav_form_data = {"file": (file_name, open(file_path, "rb"))}

            response = requests.post(
                upload_url,
                files=wav_form_data,
                headers=self.auth_headers(),
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
        response = requests.post(
            url=f"{self.URL}/api/v2/users/{user_id}/password",
            data=json.dumps(body),
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/message/recipients",
            params=parameters,
            headers=self.auth_headers(),
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
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/checkin",
            params=parameters,
            headers=self.auth_headers(),
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
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/checkout",
            params=parameters,
            headers=self.auth_headers(),
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
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/actions/publish",
            params=parameters,
            headers=self.auth_headers(),
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
        url = f"{self.URL}/api/v2/flows/{flow_id}/latestConfiguration"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/executions/{execution_id}",
            headers=self.auth_headers(),
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
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/executions",
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/scorecards/users/{user_id}?workday={workday}&expand=objective",
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/profiles/users/{user_id}?workday={workday}",
            headers=self.auth_headers(),
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
        response = requests.get(
            url=f"{self.URL}/api/v2/gamification/profiles/{profile_id}/metrics/{metric_id}",
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({profile_id=}, {metric_id=}){content}"
            raise Exception(erro)
        return response.json()

    def get_attributes_conversations_by_query(self, body: dict) -> dict:
        """
        POST /api/v2/conversations/participants/attributes/search \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/conversations/participants/attributes/search",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_attributes_conversations_by_query({body=}){content}"
            raise Exception(erro)
        return response.json()
        
    def disconnect_conversations_by_id(self, conversation_id: str) -> None:
        """
        POST /api/v2/conversations/${input.conversationId}/disconnect \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        body = {}
        response = requests.post(
            url=f"{self.URL}/api/v2/conversations/{conversation_id}/disconnect",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"disconnect_conversations_by_id({body=}){content}"
            raise Exception(erro)
        return None
    
    def get_users(
        self, body: dict = {}, page_number: int = 1, page_size: int = 25
    ) -> dict:
        """
        POST /api/v2/users/search HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplos:

        Body para pesquisar nome de usuário ativo e inativo

        {
            "pageSize": (page_size),
            "pageNumber": (page_number),
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

        Body para pesquisar email de usuario ativo e inativo

        {
            "pageSize": (page_size),
            "pageNumber": (page_number),
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

        Body default

        {
            "pageSize": page_size,
            "pageNumber": page_number,
            "query": [
                {
                "type": "EXACT",
                "fields": [
                    "state"
                ],
                "values": [
                    "active"
                ]
                }
            ],
            "sortOrder": "ASC",
            "sortBy": "name",
            "expand": [
                "images",
                "authorization",
                "team",
                "routingStatus",
                "presence",
                "organization",
                "dateLastLogin",
                "integrationPresence",
                "presence",
                "routingskills",
                "routinglanguages",
                "token",
                "groups"
            ],
            "enforcePermissions": True
        }
        """
        name_function = "get_users"
        if not body:
            body = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "query": [
                    {
                    "type": "EXACT",
                    "fields": [
                        "state"
                    ],
                    "values": [
                        "active"
                    ]
                    }
                ],
                "sortOrder": "ASC",
                "sortBy": "name",
                "expand": [
                    "images",
                    "authorization",
                    "team",
                    "routingStatus",
                    "presence",
                    "organization",
                    "dateLastLogin",
                    "integrationPresence",
                    "presence",
                    "routingskills",
                    "routinglanguages",
                    "token",
                    "groups"
                ],
                "enforcePermissions": True
            }
        response = requests.post(
            url=f"{self.URL}/api/v2/users/search",
            data=json.dumps(body),
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_events_audits(self, body: dict) -> dict:
        """
        POST /api/v2/audits/query/realtime \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/audits/query/realtime?expand=user",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_events_audits({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_events_usage(self, body: dict, params: dict|None = None) -> dict:
        """
        POST /api/v2/usage/events/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        if not params:
            params = {
                "pageSize": 25,
            }
        response = requests.post(
            url=f"{self.URL}/api/v2/usage/events/query",
            headers=self.auth_headers(),
            params=params,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_events_usage({body=}){content}"
            raise Exception(erro)
        return response.json()