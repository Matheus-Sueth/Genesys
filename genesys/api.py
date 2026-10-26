import requests
from urllib.parse import quote
from genesys.platform_api import PlatformAPIClient
from genesys.inventory_http import inventory_get
from genesys.inventory_wave2 import inventory_get_wave2
import base64
import os
import time
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
    def get_region(self) -> GenesysRegion: ...
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

    def get_region(self) -> GenesysRegion:
        return self.region

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

    def get_region(self) -> GenesysRegion:
        return self.region

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
    def __init__(self, token_provider: TokenProvider) -> None:
        self.region = token_provider.get_region()
        self.URL_AUTH = self.region.url_auth
        self.URL = self.region.url_api
        self.token_provider = token_provider
        self.information_token = self.get_information_token()
        
    def __str__(self) -> str:
        return f"Genesys(org: {self.information_token['organization']['name']}, user: {self.information_token['OAuthClient']['name']})"
    
    def get_organization_name(self) -> str:
        return self.information_token['organization']['name']
    
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
        url = f"{self.URL}/api/v2/tokens/me"
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

    def get_architect_prompts(
        self,
        parameters: dict
    ) -> dict:
        """
        GET /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_architect_prompts"
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
        parameters = {"showbrief": False}
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
    
    def get_integrations_actions(self, params: dict) -> dict:
        """
        GET /api/v2/integrations/actions HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_data_action_by_name"
        response = requests.get(
            url=f"{self.URL}/api/v2/integrations/actions",
            params=params,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
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
    
    def post_architect_prompts(self, body: dict) -> dict:
        """
        POST /api/v2/architect/prompts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "post_architect_prompts"
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

    def post_architect_prompts_resources_by_id(self, prompt_id: str, body: dict) -> dict:
        """
        POST /api/v2/architect/prompts/{promptId}/resources HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "post_architect_prompts_resources_by_id"
        response = requests.post(
            url=f"{self.URL}/api/v2/architect/prompts/{prompt_id}/resources",
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
            time.sleep(3)
            dados = self.checkin_flow_by_id(flow_id)
            print(flow["name"], dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados["currentOperation"]
            print(f"{flow["name"]} - id: {current_operation["id"]}")
            print(f"{flow["name"]} - action name: {current_operation["actionName"]}")
            status = current_operation["actionStatus"]
            print(f"{flow["name"]} - action status: {status}")
            time.sleep(3)
            dados = self.publish_flow_by_id(flow_id)
            print(flow["name"], dados)
            dados = self.get_flow_by_id(flow_id)
            current_operation = dados["currentOperation"]
            print(f"{flow["name"]} - id: {current_operation["id"]}")
            print(f"{flow["name"]} - action name: {current_operation["actionName"]}")
            status = current_operation["actionStatus"]
            print(f"{flow["name"]} - action status: {status}")
            time.sleep(3)
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
    
    def get_usage_events(self, body: dict, params: dict|None = None, next_url: str|None = None) -> dict:
        """
        POST /api/v2/usage/events/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        if not params:
            params = {
                "pageSize": 25,
            }
        url = f"{self.URL}{next_url}" if next_url else f"{self.URL}/api/v2/usage/events/query"
        response = requests.post(
            url=url,
            headers=self.auth_headers(),
            params=params,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_usage_events({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_routing_queues(self, params: dict|None = None) -> dict:
        """
        GET /api/v2/routing/queues \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplo:

        {
            "pageSize": 100,
            "pageNumber": 1,
            "sortOrder": "asc",
            "sortBy": "name"
        }
        """
        if not params:
            params = {
                "pageSize": 100,
                "pageNumber": 1,
                "sortOrder": "asc",
                "sortBy": "name"
            }
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/queues",
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_routing_queues({params=}){content}"
            raise Exception(erro)
        return response.json()

    def post_row_data_table(
        self,
        data_table_id: str,
        body: dict,
    ) -> dict:
        """
        POST /api/v2/flows/datatables/{datatableId}/rows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "post_row_data_table"
        url = f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows"
        response = requests.post(
            url=url,
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{data_table_id=}, {body=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()
    
    def put_row_data_table_by_id(
        self,
        data_table_id: str,
        row_id: str,
        body: dict
    ) -> dict:
        """
        PUT /api/v2/flows/datatables/{datatableId}/rows/{rowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "put_row_data_table_by_id"
        url = f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows/{row_id}"
        response = requests.put(
            url=url,
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{data_table_id=}, {row_id=}, {body=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()
    
    def delete_row_data_table_by_id(
        self,
        data_table_id: str,
        row_id: str,
    ) -> dict:
        """
        DELETE /api/v2/flows/datatables/{datatableId}/rows/{rowId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "delete_row_data_table_by_id"
        url = f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows/{row_id}"
        response = requests.delete(
            url=url,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            parameters = f"{data_table_id=}, {row_id=}"
            erro = f"{name_function}({parameters}){content}"
            raise Exception(erro)
        return response.json()

    def post_groups_members(self, group_id: str, body: dict) -> dict:
        """
        POST /api/v2/groups/{groupId}/members \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        BI: 9f5c0649-b806-45cb-ade4-4834980d58d2
        body = [userId]
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/groups/{group_id}/members",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_groups_members({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def post_usage_events_aggregates(self, body: dict) -> dict:
        """
        POST /api/v2/usage/events/aggregates/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/usage/events/aggregates/query",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_usage_events_aggregates({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def post_analytics_queues_observations_query(self, body: dict) -> dict:
        """
        POST /api/v2/analytics/queues/observations/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Body empty schema

        {
        "filter": {
            "type": "",
            "clauses": [
            {
                "type": "",
                "predicates": [
                {
                    "type": "",
                    "dimension": "",
                    "operator": "",
                    "value": "",
                    "range": ""
                }
                ]
            }
            ],
            "predicates": []
        },
        "metrics": [],
        "detailMetrics": []
        }
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/analytics/queues/observations/query",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_analytics_queues_observations_query({body=}){content}"
            raise Exception(erro)
        return response.json()

    def get_conversation_summaries_by_id(self, conversation_id: str) -> dict:
        """
        GET /api/v2/conversations/{conversationId}/summaries \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/conversations/{conversation_id}/summaries', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_conversation_summaries_by_id({conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_speech_conversation_summaries_by_id(self, conversation_id: str) -> dict:
        """
        GET /api/v2/speechandtextanalytics/conversations/{conversationId}/summaries \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(url=f'{self.URL}/api/v2/speechandtextanalytics/conversations/{conversation_id}/summaries', headers=self.auth_headers())
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_speech_conversation_summaries_by_id({conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_queues_memebers_by_id(
        self, queueu_id: str, params: dict = {}, page_number: int = 1, page_size: int = 100
    ) -> dict:
        """
        GET /api/v2/routing/queues/{queueId}/members HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplos de params:
        
        params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC",
                "sortBy": "name"
            }
        """
        name_function = "get_queues_memebers_by_id"
        if not params:
            params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC",
            }
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/queues/{queueu_id}/members",
            params=params,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({queueu_id=},{params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def path_user_by_id(self, user_id: str, body: dict) -> dict:
        """
        PATCH /api/v2/users/{userId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.patch(
            url=f'{self.URL}/api/v2/users/{user_id}', 
            headers=self.auth_headers(),
            data=json.dumps(body)
            )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"path_user_by_id({user_id=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def put_user_by_id(self, user_id: str, body: dict) -> dict:
        """
        PUT /api/v2/users/{userId}/state \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.put(
            url=f'{self.URL}/api/v2/users/{user_id}/state', 
            headers=self.auth_headers(),
            data=json.dumps(body)
            )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"put_user_by_id({user_id=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_authorization_roles(
        self, params: dict = {}, page_number: int = 1, page_size: int = 100
    ) -> dict:
        """
        GET /api/v2/authorization/roles HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplos de params:
        
        params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC"
            }
        """
        name_function = "get_authorization_roles"
        if not params:
            params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC",
            }
        response = requests.get(
            url=f"{self.URL}/api/v2/authorization/roles",
            params=params,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_authorization_divisions(
        self, params: dict = {}, page_number: int = 1, page_size: int = 100
    ) -> dict:
        """
        GET /api/v2/authorization/divisions HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplos de params:
        
        params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC"
            }
        """
        name_function = "get_authorization_divisions"
        if not params:
            params = {
                "pageSize": page_size,
                "pageNumber": page_number,
                "sortOrder": "ASC",
            }
        response = requests.get(
            url=f"{self.URL}/api/v2/authorization/divisions",
            params=params,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_user_roles(self, subject_id: str) -> dict:
        """
        GET /api/v2/users/{subjectId}/roles \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        subject_id = user_id
        """
        response = requests.get(
            url=f'{self.URL}/api/v2/users/{subject_id}/roles', 
            headers=self.auth_headers()
            )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_user_roles({subject_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_user_by_id(self, user_id: str, parameters: dict|None = None) -> dict:
        """
        GET /api/v2/users/{userId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f'{self.URL}/api/v2/users/{user_id}', 
            headers=self.auth_headers(),
            params=parameters
            )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_user_by_id({user_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def put_user_roles_by_id(self, subject_id: str, body: dict) -> dict:
        """
        PUT /api/v2/users/{subjectId}/roles \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.put(
            url=f'{self.URL}/api/v2/users/{subject_id}/roles', 
            headers=self.auth_headers(),
            data=json.dumps(body)
            )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"put_user_roles_by_id({subject_id=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_rows_data_table_by_id(
        self,
        data_table_id: str,
        page_number: int = 1,
        page_size: int = 50,
        showbrief: bool = False,
        sort_order: str = "ascending",
    ) -> dict:
        """
        GET /api/v2/flows/datatables/{datatableId}/rows HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_rows_data_table_by_id"
        parameters = {
            "showbrief": showbrief,
            "pageNumber": page_number,
            "pageSize": page_size,
            "sortOrder": sort_order,
        }
        response = requests.get(
            url=f"{self.URL}/api/v2/flows/datatables/{data_table_id}/rows",
            params=parameters,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({parameters=}){content}"
            raise Exception(erro)
        return response.json()
    
    def post_flows_intances_query(self, body: dict, params: dict|None = None) -> dict:
        """
        POST /api/v2/flows/instances/query \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        if not params:
            params = {
                "pageSize": 25,
            }
        response = requests.post(
            url=f"{self.URL}/api/v2/flows/instances/query",
            headers=self.auth_headers(),
            params=params,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_flows_intances_query({params=}, {body=}){content}"
            raise Exception(erro)
        return response.json()

    def post_routing_wrapupcodes(self, body: dict) -> dict:
        """
        POST /api/v2/routing/wrapupcodes \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        {"name":"te","description":"res","division":{"id":"*"}}
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/routing/wrapupcodes",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_routing_wrapupcodes({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_routing_wrapupcodes(self, params: dict|None = None) -> dict:
        """
        GET /api/v2/routing/wrapupcodes \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        params:
        
        {
            "pageSize": 25,
            "pageNumber": 1,
            "sortOrder": "ascending",
            "name": ""
        }
        """
        if not params:
            params = {
                "pageSize": 25,
                "pageNumber": 1,
                "sortOrder": "ascending"
            }
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/wrapupcodes",
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_flows_intances_query({params=}){content}"
            raise Exception(erro)
        return response.json()

    def post_routing_queue_wrapupcodes_by_id(self, queue_id: str, body: list[dict[str, str]]) -> dict:
        """
        POST /api/v2/routing/queues/{queueId}/wrapupcodes \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        [{"id":""}]
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/routing/queues/{queue_id}/wrapupcodes",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_routing_queue_wrapupcodes_by_id({queue_id=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def put_routing_wrapupcodes(self, wrap_up_code_id: str, body: dict) -> dict:
        """
        PUT /api/v2/routing/wrapupcodes/{codeId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        {"name":"te","description":"res","division":{"id":"*"}}
        """
        response = requests.put(
            url=f"{self.URL}/api/v2/routing/wrapupcodes/{wrap_up_code_id}",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"put_routing_wrapupcodes({wrap_up_code_id=},{body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_script_by_id(self, script_id: str) -> dict:
        """
        GET /api/v2/scripts/{scriptId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_script_by_id"
        url = f"{self.URL}/api/v2/scripts/{script_id}"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({script_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_scripts(self, params: dict) -> dict:
        """
        GET /api/v2/scripts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_script_by_id"
        url = f"{self.URL}/api/v2/scripts"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_architect_dependency_tracking(self, params: dict) -> dict:
        """
        GET /api/v2/architect/dependencytracking/object \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_architect_dependency_tracking"
        response = requests.get(
            url=f"{self.URL}/api/v2/architect/dependencytracking/object",
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_integration_action_by_id(self, action_id: str) -> dict:
        """
        GET /api/v2/integrations/actions/{actionId} HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_integration_action_by_id"
        response = requests.get(
            url=f"{self.URL}/api/v2/integrations/actions/{action_id}",
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({action_id=}){content}"
            raise Exception(erro)
        return response.json()

    def get_integration_action_draft_by_id(self, action_id: str) -> dict:
        """
        GET /api/v2/integrations/actions/{actionId}/draft HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        name_function = "get_integration_action_draft_by_id"
        response = requests.get(
            url=f"{self.URL}/api/v2/integrations/actions/{action_id}/draft",
            headers=self.auth_headers(),
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({action_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def put_routing_queue(self, queue_id: str, body: dict) -> dict:
        """
        PUT /api/v2/routing/queues/{queueId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        {
            "name": "",
            "division": {
                "id": "",
                "name": ""
            },
            "description": "",
            "dateCreated": "",
            "dateModified": "",
            "modifiedBy": "",
            "createdBy": "",
            "mediaSettings": {
                "call": {
                "enableAutoAnswer": true,
                "alertingTimeoutSeconds": 0,
                "serviceLevel": "",
                "autoAnswerAlertToneSeconds": 0,
                "manualAnswerAlertToneSeconds": 0
                },
                "callback": {
                "enableAutoAnswer": true,
                "alertingTimeoutSeconds": 0,
                "serviceLevel": "",
                "autoAnswerAlertToneSeconds": 0,
                "manualAnswerAlertToneSeconds": 0,
                "mode": "",
                "enableAutoDialAndEnd": true,
                "autoDialDelaySeconds": 0,
                "autoEndDelaySeconds": 0,
                "pacingModifier": 0,
                "maxRetryCount": 0,
                "retryDelaySeconds": 0,
                "liveVoiceReactionType": "",
                "liveVoiceFlow": "",
                "answeringMachineReactionType": "",
                "answeringMachineFlow": "",
                "edgeGroup": "",
                "site": ""
                },
                "chat": {
                "enableAutoAnswer": true,
                "alertingTimeoutSeconds": 0,
                "serviceLevel": "",
                "autoAnswerAlertToneSeconds": 0,
                "manualAnswerAlertToneSeconds": 0
                },
                "email": {
                "enableAutoAnswer": true,
                "alertingTimeoutSeconds": 0,
                "serviceLevel": "",
                "autoAnswerAlertToneSeconds": 0,
                "manualAnswerAlertToneSeconds": 0
                },
                "message": {
                "enableAutoAnswer": true,
                "alertingTimeoutSeconds": 0,
                "serviceLevel": "",
                "autoAnswerAlertToneSeconds": 0,
                "manualAnswerAlertToneSeconds": 0,
                "subTypeSettings": {},
                "enableInactivityTimeout": true,
                "inactivityTimeoutSettings": ""
                }
            },
            "routingRules": [
                {
                "operator": "",
                "threshold": 0,
                "waitSeconds": 0
                }
            ],
            "conditionalGroupRouting": {
                "rules": [
                {
                    "queue": "",
                    "metric": "",
                    "operator": "",
                    "conditionValue": 0,
                    "groups": [
                    {
                        "id": "",
                        "name": "",
                        "division": "",
                        "type": ""
                    }
                    ],
                    "waitSeconds": 0
                }
                ]
            },
            "conditionalGroupActivation": {
                "pilotRule": {
                "conditions": [
                    {
                    "simpleMetric": "",
                    "operator": "",
                    "value": 0
                    }
                ],
                "conditionExpression": ""
                },
                "rules": [
                {
                    "conditions": [
                    ""
                    ],
                    "conditionExpression": "",
                    "groups": [
                    ""
                    ]
                }
                ]
            },
            "bullseye": {
                "rings": [
                {
                    "expansionCriteria": [
                    {
                        "type": "",
                        "threshold": 0
                    }
                    ],
                    "actions": "",
                    "memberGroups": [
                    ""
                    ]
                }
                ]
            },
            "scoringMethod": "",
            "lastAgentRoutingMode": "",
            "acwSettings": {
                "wrapupPrompt": "",
                "timeoutMs": 0
            },
            "skillEvaluationMethod": "",
            "memberGroups": [
                ""
            ],
            "queueFlow": {
                "id": "",
                "name": "",
                "selfUri": ""
            },
            "emailInQueueFlow": {
                "id": "",
                "name": "",
                "selfUri": ""
            },
            "messageInQueueFlow": {
                "id": "",
                "name": "",
                "selfUri": ""
            },
            "whisperPrompt": {
                "id": "",
                "name": "",
                "selfUri": ""
            },
            "onHoldPrompt": {
                "id": "",
                "name": "",
                "selfUri": ""
            },
            "autoAnswerOnly": true,
            "cannedResponseLibraries": {
                "libraryIds": [
                ""
                ],
                "mode": ""
            },
            "enableTranscription": true,
            "enableAudioMonitoring": true,
            "enableManualAssignment": true,
            "agentOwnedRouting": {
                "enableAgentOwnedCallbacks": true,
                "maxOwnedCallbackHours": 0,
                "maxOwnedCallbackDelayHours": 0
            },
            "directRouting": {
                "callMediaSettings": {
                "useAgentAddressOutbound": true
                },
                "emailMediaSettings": {
                "useAgentAddressOutbound": true
                },
                "messageMediaSettings": {
                "useAgentAddressOutbound": true
                },
                "backupQueueId": "",
                "waitForAgent": true,
                "agentWaitSeconds": 0
            },
            "callingPartyName": "",
            "callingPartyNumber": "",
            "defaultScripts": {
                "": {}
            },
            "outboundMessagingAddresses": {
                "smsAddress": {
                "id": "",
                "name": "",
                "selfUri": ""
                },
                "openMessagingRecipient": {
                "id": "",
                "name": "",
                "selfUri": ""
                },
                "whatsAppRecipient": {
                "id": "",
                "name": "",
                "selfUri": ""
                }
            },
            "outboundEmailAddress": {
                "domain": {
                "id": "",
                "name": "",
                "selfUri": ""
                },
                "route": {
                "name": "",
                "pattern": "",
                "queue": "",
                "priority": 0,
                "skills": [
                    {
                    "id": "",
                    "name": "",
                    "selfUri": ""
                    }
                ],
                "language": "",
                "fromName": "",
                "fromEmail": "",
                "flow": "",
                "replyEmailAddress": "",
                "autoBcc": [
                    {
                    "email": "",
                    "name": ""
                    }
                ],
                "spamFlow": "",
                "signature": "",
                "historyInclusion": "",
                "allowMultipleActions": true,
                "mailboxFolders": [
                    ""
                ]
                }
            },
            "peerId": "",
            "suppressInQueueCallRecording": true
            }
        """
        response = requests.put(
            url=f"{self.URL}/api/v2/routing/queues/{queue_id}",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"put_routing_queue({queue_id=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_routing_queue(self, queue_id: str) -> dict:
        """
        GET /api/v2/routing/queues/{queueId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/queues/{queue_id}",
            headers=self.auth_headers()
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_routing_queue({queue_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_routing_queue_wrapupcodes_by_id(self, queue_id: str, params: dict) -> dict:
        """
        GET /api/v2/routing/queues/{queueId}/wrapupcodes \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f"{self.URL}/api/v2/routing/queues/{queue_id}/wrapupcodes",
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_routing_queue_wrapupcodes_by_id({queue_id=}, {params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def delete_routing_queue_wrapupcode_by_id(self, queue_id: str, wrapup_code_id: str) -> None:
        """
        DELETE /api/v2/routing/queues/{queueId}/wrapupcodes/{codeId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.delete(
            url=f"{self.URL}/api/v2/routing/queues/{queue_id}/wrapupcodes/{wrapup_code_id}",
            headers=self.auth_headers()
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"delete_routing_queue_wrapupcodes_by_id({queue_id=}, {wrapup_code_id=}){content}"
            raise Exception(erro)
        return None
    
    def post_gdpr_request(self, parameters: dict, body: dict) -> dict:
        """
        POST /api/v2/gdpr/requests \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        {
            "name": "",
            "replacementTerms": [
                {
                "type": "",
                "existingValue": "",
                "updatedValue": ""
                }
            ],
            "requestType": "",
            "subject": {
                "name": "",
                "userId": "",
                "externalContactId": "",
                "dialerContactId": {
                "id": "",
                "contactListId": ""
                },
                "journeyCustomer": {
                "type": "",
                "id": ""
                },
                "socialHandle": {
                "type": "",
                "value": ""
                },
                "externalId": "",
                "addresses": [
                ""
                ],
                "phoneNumbers": [
                ""
                ],
                "emailAddresses": [
                ""
                ]
            }
            }
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/gdpr/requests",
            headers=self.auth_headers(),
            params=parameters,
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_gdpr_request({parameters=}, {body=}){content}"
            raise Exception(erro)
        return response.json()
   
    def get_gdpr_subjects(self, params: dict) -> dict:
        """
        GET /api/v2/gdpr/subjects \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f"{self.URL}/api/v2/gdpr/subjects",
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_gdpr_subjects({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_gdpr_request_by_id(self, request_id: str) -> dict:
        """
        GET /api/v2/gdpr/requests/{requestId} \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f"{self.URL}/api/v2/gdpr/requests/{request_id}",
            headers=self.auth_headers()
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_gdpr_request_by_id({request_id=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_external_contacts(self, params: dict) -> dict:
        """
        GET /api/v2/externalcontacts/contacts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_external_contacts"
        url = f"{self.URL}/api/v2/externalcontacts/contacts"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def get_external_contacts_scan(self, params: dict) -> dict:
        """
        GET /api/v2/externalcontacts/scan/contacts HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json \n
        """
        name_function = "get_external_contacts_scan"
        url = f"{self.URL}/api/v2/externalcontacts/scan/contacts"
        response = requests.get(
            url=url,
            headers=self.auth_headers(),
            params=params
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({params=}){content}"
            raise Exception(erro)
        return response.json()
    
    def post_users(self, body: dict) -> dict:
        """
        POST /api/v2/users \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        body:

        {
            "name": "",
            "department": "",
            "email": "",
            "addresses": [
                {
                "address": "",
                "mediaType": "",
                "type": "",
                "extension": "",
                "countryCode": "",
                "integration": ""
                }
            ],
            "title": "",
            "password": "",
            "divisionId": "",
            "state": ""
        }
        """
        response = requests.post(
            url=f"{self.URL}/api/v2/users",
            headers=self.auth_headers(),
            data=json.dumps(body)
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"post_users({body=}){content}"
            raise Exception(erro)
        return response.json()
    
    def post_authorization_subject_bulkadd(
        self, subject_id: str, params: dict|None = None, body: dict|None = None
    ) -> dict:
        """
        GET /api/v2/authorization/subjects/{subjectId}/bulkadd HTTP/1.1 \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json

        Exemplos de params:
        
        params = 
        {
            "subjectType": what the type of the subject is (PC_GROUP, PC_USER or PC_OAUTH_CLIENT)
        }

        body = 
        {
            "grants": [
                {
                "roleId": "",
                "divisionId": ""
                }
            ]
        }

        """
        name_function = "post_authorization_subject_bulkadd"
        response = requests.post(
            url=f"{self.URL}/api/v2/authorization/subjects/{subject_id}/bulkadd",
            params=params,
            headers=self.auth_headers(),
            json=body
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"{name_function}({subject_id=},{params=}, {body=}){content}"
            raise Exception(erro)
        return response.json()

    def get_analytics_conversations_details(self, list_conversation_id: list[str]) -> dict:
        """
        GET /api/v2/analytics/conversations/details \n
        Authorization: Bearer ****************** \n
        Content-Type: application/json
        """
        response = requests.get(
            url=f'{self.URL}/api/v2/analytics/conversations/details', 
            headers=self.auth_headers(),
            params={
                "id": ",".join(list_conversation_id)
            }
        )
        if not response.ok:
            content = f"\nContent: {response.content}\n"
            erro = f"get_analytics_conversations_details({list_conversation_id=}){content}"
            raise Exception(erro)
        return response.json()
    

    # Métodos de inventário: GET-only, compatíveis com PKCE e Client Credentials.
    def _inventory_get(
        self, path: str, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        return inventory_get(
            self, path, params=params, all_pages=all_pages, max_pages=max_pages,
            page_size=page_size, timeout=timeout,
        )

    def get_inventory_organization(self, *, timeout: tuple[int, int] = (5, 30)) -> dict:
        """GET /api/v2/organizations/me; retorna o payload original."""
        return self._inventory_get("/api/v2/organizations/me", timeout=timeout)

    def get_inventory_routing_settings(self, *, timeout: tuple[int, int] = (5, 30)) -> dict:
        """GET /api/v2/routing/settings; retorna o payload original."""
        return self._inventory_get("/api/v2/routing/settings", timeout=timeout)

    def get_inventory_telephony_settings(self, *, timeout: tuple[int, int] = (5, 30)) -> dict:
        """GET /api/v2/telephony/settings; retorna o payload original."""
        return self._inventory_get("/api/v2/telephony/settings", timeout=timeout)

    def get_inventory_users(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/users; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/users", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_groups(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/groups; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/groups", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_routing_skills(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/skills; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/routing/skills", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_routing_languages(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/languages; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/routing/languages", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_data_tables(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/flows/datatables; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/flows/datatables", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_schedules(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/architect/schedules; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/architect/schedules", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_schedule_groups(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/architect/schedulegroups; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/architect/schedulegroups", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_emergency_groups(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/architect/emergencygroups; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/architect/emergencygroups", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_integrations(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/integrations; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/integrations", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_queue_division_views_all(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/queues/divisionviews/all; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/routing/queues/divisionviews/all", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_telephony_sites(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/telephony/providers/edges/sites; all_pages=True retorna uma lista completa."""
        return self._inventory_get(
            "/api/v2/telephony/providers/edges/sites", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )


    # Onda 2: inventário e governança, somente GET.
    def _inventory_get_wave2(
        self, path: str, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        return inventory_get_wave2(
            self, path, params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_skill_groups(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/skillgroups; modo de paginação: cursor."""
        return self._inventory_get_wave2(
            "/api/v2/routing/skillgroups", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_email_domains(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/email/domains; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/routing/email/domains", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_sms_phone_numbers(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/routing/sms/phonenumbers; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/routing/sms/phonenumbers", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_telephony_edge_groups(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/telephony/providers/edges/edgegroups; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/telephony/providers/edges/edgegroups", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_telephony_outbound_routes(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/telephony/providers/edges/outboundroutes; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/telephony/providers/edges/outboundroutes", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_telephony_did_pools(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/telephony/providers/edges/didpools; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/telephony/providers/edges/didpools", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_telephony_dids(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/telephony/providers/edges/dids; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/telephony/providers/edges/dids", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_oauth_clients(self, *, timeout: tuple[int, int] = (5, 30)) -> dict:
        """GET /api/v2/oauth/clients; campos OAuth sensíveis são mascarados."""
        return self._inventory_get_wave2("/api/v2/oauth/clients", timeout=timeout)

    def get_inventory_authorization_permissions(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/authorization/permissions; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/authorization/permissions", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_media_retention_policies(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/recording/mediaretentionpolicies; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/recording/mediaretentionpolicies", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_outbound_campaigns(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/outbound/campaigns; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/outbound/campaigns", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_web_deployments(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/webdeployments/deployments; modo de paginação: cursor."""
        return self._inventory_get_wave2(
            "/api/v2/webdeployments/deployments", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_quality_evaluation_forms(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/quality/forms/evaluations; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/quality/forms/evaluations", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_knowledge_bases(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/knowledge/knowledgebases; modo de paginação: cursor."""
        return self._inventory_get_wave2(
            "/api/v2/knowledge/knowledgebases", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_flow_milestones(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/flows/milestones; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/flows/milestones", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def get_inventory_flow_outcomes(
        self, *, params: dict | None = None, all_pages: bool = False,
        max_pages: int = 25, page_size: int = 100,
        timeout: tuple[int, int] = (5, 30),
    ) -> dict | list:
        """GET /api/v2/flows/outcomes; modo de paginação: page_number."""
        return self._inventory_get_wave2(
            "/api/v2/flows/outcomes", params=params, all_pages=all_pages,
            max_pages=max_pages, page_size=page_size, timeout=timeout,
        )

    def _request_platform_api(
        self, method: str, path: str, *, params: dict | None = None,
        body=None, data=None, files=None, headers: dict | None = None,
        timeout: int | float = 30, max_retries: int = 2,
        response_mode: str = "auto",
    ):
        """Executor HTTP compartilhado pelas operações explícitas desta classe.

        Use `body` para JSON, `data`/`files` para uploads, e `headers` para
        cabeçalhos próprios da operação. GET pode ser tentado novamente em 429;
        chamadas que modificam dados nunca são repetidas automaticamente.
        `response_mode`: auto, json, text, bytes ou response.
        """
        import time as _time
        from datetime import datetime as _datetime, timezone as _timezone
        from email.utils import parsedate_to_datetime as _parsedate

        method = method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Método HTTP não suportado")
        if not path.startswith("/api/v2/") or any(ch in path for ch in ("?", "#", "\\")):
            raise ValueError("A rota deve ser um caminho da Platform API sem query string")
        if timeout <= 0 or not isinstance(max_retries, int) or not (0 <= max_retries <= 5):
            raise ValueError("Timeout ou quantidade de tentativas inválidos")
        if response_mode not in {"auto", "json", "text", "bytes", "response"}:
            raise ValueError("response_mode inválido")
        if body is not None and (data is not None or files is not None):
            raise ValueError("Use body (JSON) ou data/files (raw/multipart), não ambos")
        if headers and any(k.lower() == "authorization" for k in headers):
            raise ValueError("Authorization é gerenciado pelo TokenProvider")

        request_headers = self.auth_headers()
        if files is not None or data is not None:
            request_headers.pop("Content-Type", None)
        if headers:
            request_headers.update(headers)
        request_args = {
            "headers": request_headers,
            "timeout": timeout,
            "allow_redirects": False,
        }
        if params is not None:
            request_args["params"] = params
        if body is not None:
            request_args["json"] = body
        if data is not None:
            request_args["data"] = data
        if files is not None:
            request_args["files"] = files

        url = self.URL.rstrip("/") + path
        for attempt in range(max_retries + 1 if method == "GET" else 1):
            response = requests.request(method, url, **request_args)
            if response.status_code == 429 and method == "GET" and attempt < max_retries:
                retry_after = response.headers.get("Retry-After", "")
                try:
                    delay = max(0.0, float(retry_after))
                except (ValueError, TypeError):
                    try:
                        date = _parsedate(retry_after)
                        if date.tzinfo is None:
                            date = date.replace(tzinfo=_timezone.utc)
                        delay = max(0.0, (date - _datetime.now(_timezone.utc)).total_seconds())
                    except (ValueError, TypeError, IndexError):
                        delay = min(2 ** attempt, 30)
                if delay > 60:
                    raise RuntimeError("Genesys Cloud 429: Retry-After superior a 60s; tente posteriormente")
                _time.sleep(delay)
                continue
            if not (200 <= response.status_code < 300):
                raise RuntimeError(f"Genesys Cloud API {method} falhou: HTTP {response.status_code}")
            if response_mode == "response":
                return response
            if response.status_code == 204 or not response.content:
                return None
            if response_mode == "bytes":
                return response.content
            if response_mode == "text":
                return response.text
            content_type = response.headers.get("Content-Type", "").split(";")[0].lower()
            if response_mode == "json" or content_type.endswith("+json") or content_type == "application/json":
                return response.json()
            if content_type.startswith("text/"):
                return response.text
            return response.content
        raise RuntimeError("Número máximo de tentativas GET atingido")

    def get_agentic_virtualagents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/agentic/virtualagents', params=params, **kwargs)

    def post_agentic_virtualagents(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/agentic/virtualagents', params=params, body=body, **kwargs)

    def get_agentic_virtualagent(self, virtual_agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}", params=params, **kwargs)

    def patch_agentic_virtualagent(self, virtual_agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}", params=params, body=body, **kwargs)

    def delete_agentic_virtualagent_jobs(self, virtual_agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_agentic_virtualagent_job(self, job_id, virtual_agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_agentic_virtualagent_versions(self, virtual_agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/versions", params=params, body=body, **kwargs)

    def get_agentic_virtualagent_version(self, version_id, virtual_agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def patch_agentic_virtualagent_version(self, version_id, virtual_agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, body=body, **kwargs)

    def post_agentic_virtualagent_version_jobs(self, version_id, virtual_agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/versions/{quote(str(version_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_agentic_virtualagent_version_job(self, job_id, version_id, virtual_agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/agentic/virtualagents/{quote(str(virtual_agent_id), safe='')}/versions/{quote(str(version_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def delete_alerting_alerts_all(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/alerting/alerts/all', params=params, body=body, **kwargs)

    def patch_alerting_alerts_all(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/alerting/alerts/all', params=params, body=body, **kwargs)

    def patch_alerting_alerts_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/alerting/alerts/bulk', params=params, body=body, **kwargs)

    def post_alerting_alerts_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/alerting/alerts/query', params=params, body=body, **kwargs)

    def delete_alerting_alert(self, alert_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/alerting/alerts/{quote(str(alert_id), safe='')}", params=params, body=body, **kwargs)

    def get_alerting_alert(self, alert_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/alerting/alerts/{quote(str(alert_id), safe='')}", params=params, **kwargs)

    def patch_alerting_alert(self, alert_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/alerting/alerts/{quote(str(alert_id), safe='')}", params=params, body=body, **kwargs)

    def put_alerting_alert(self, alert_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/alerting/alerts/{quote(str(alert_id), safe='')}", params=params, body=body, **kwargs)

    def post_alerting_rules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/alerting/rules', params=params, body=body, **kwargs)

    def patch_alerting_rules_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/alerting/rules/bulk', params=params, body=body, **kwargs)

    def post_alerting_rules_bulk_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/alerting/rules/bulk/remove', params=params, body=body, **kwargs)

    def post_alerting_rules_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/alerting/rules/query', params=params, body=body, **kwargs)

    def delete_alerting_rule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/alerting/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_alerting_rule(self, rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/alerting/rules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def put_alerting_rule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/alerting/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def post_analytics_actions_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/actions/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_actions_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/actions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_actions_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/actions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_actions_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/actions/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_agentcopilots_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/agentcopilots/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_agentcopilots_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/agentcopilots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_agentcopilots_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/agentcopilots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_agentcopilots_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/agentcopilots/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_agentcopilots_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/agentcopilots/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_agents_status_counts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/agents/status/counts', params=params, body=body, **kwargs)

    def post_analytics_agents_status_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/agents/status/query', params=params, body=body, **kwargs)

    def get_analytics_agent_status(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/agents/{quote(str(user_id), safe='')}/status", params=params, **kwargs)

    def get_analytics_botflow_divisions_reportingturns(self, bot_flow_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/botflows/{quote(str(bot_flow_id), safe='')}/divisions/reportingturns", params=params, **kwargs)

    def get_analytics_botflow_reportingturns(self, bot_flow_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/botflows/{quote(str(bot_flow_id), safe='')}/reportingturns", params=params, **kwargs)

    def get_analytics_botflow_sessions(self, bot_flow_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/botflows/{quote(str(bot_flow_id), safe='')}/sessions", params=params, **kwargs)

    def post_analytics_bots_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/bots/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_bots_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/bots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_bots_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/bots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_bots_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/bots/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_bots_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/bots/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_casemanagement_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/casemanagement/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_casemanagement_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/casemanagement/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_casemanagement_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/casemanagement/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_casemanagement_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/casemanagement/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_casemanagement_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/casemanagement/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_conversations_activity_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/conversations/activity/query', params=params, body=body, **kwargs)

    def post_analytics_conversations_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/conversations/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_conversations_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/conversations/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_conversations_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/conversations/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_conversations_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/conversations/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_conversations_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/conversations/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_conversations_details_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/conversations/details/jobs', params=params, body=body, **kwargs)

    def get_analytics_conversations_details_jobs_availability(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/conversations/details/jobs/availability', params=params, **kwargs)

    def delete_analytics_conversations_details_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/conversations/details/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_conversations_details_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/conversations/details/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_conversations_details_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/conversations/details/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_conversation_details_properties(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/analytics/conversations/{quote(str(conversation_id), safe='')}/details/properties", params=params, body=body, **kwargs)

    def post_analytics_copilots_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/copilots/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_copilots_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/copilots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_copilots_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/copilots/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_copilots_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/copilots/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_copilots_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/copilots/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_dataextraction_downloads_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/dataextraction/downloads/bulk', params=params, body=body, **kwargs)

    def get_analytics_dataextraction_downloads_metadata(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/dataextraction/downloads/metadata', params=params, **kwargs)

    def get_analytics_dataextraction_download(self, download_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/dataextraction/downloads/{quote(str(download_id), safe='')}", params=params, **kwargs)

    def get_analytics_dataretention_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/dataretention/settings', params=params, **kwargs)

    def put_analytics_dataretention_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/analytics/dataretention/settings', params=params, body=body, **kwargs)

    def post_analytics_evaluations_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/evaluations/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_evaluations_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/evaluations/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_evaluations_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/evaluations/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_evaluations_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/evaluations/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_evaluations_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/evaluations/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_flowexecutions_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flowexecutions/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_flowexecutions_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/flowexecutions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_flowexecutions_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/flowexecutions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_flowexecutions_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/flowexecutions/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_flowexecutions_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flowexecutions/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_flows_activity_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flows/activity/query', params=params, body=body, **kwargs)

    def post_analytics_flows_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flows/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_flows_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/flows/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_flows_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/flows/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_flows_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/flows/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_flows_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flows/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_flows_observations_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/flows/observations/query', params=params, body=body, **kwargs)

    def post_analytics_journeys_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/journeys/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_journeys_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/journeys/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_journeys_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/journeys/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_journeys_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/journeys/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_journeys_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/journeys/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_knowledge_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/knowledge/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_knowledge_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/knowledge/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_knowledge_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/knowledge/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_knowledge_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/knowledge/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_knowledge_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/knowledge/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_ratelimits_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/ratelimits/aggregates/query', params=params, body=body, **kwargs)

    def get_analytics_reporting_dashboards_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/reporting/dashboards/users', params=params, **kwargs)

    def post_analytics_reporting_dashboards_users_bulk_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/reporting/dashboards/users/bulk/remove', params=params, body=body, **kwargs)

    def get_analytics_reporting_dashboards_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/reporting/dashboards/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def get_analytics_reporting_exports(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/reporting/exports', params=params, **kwargs)

    def post_analytics_reporting_exports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/reporting/exports', params=params, body=body, **kwargs)

    def get_analytics_reporting_exports_metadata(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/reporting/exports/metadata', params=params, **kwargs)

    def get_analytics_reporting_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/reporting/settings', params=params, **kwargs)

    def patch_analytics_reporting_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/analytics/reporting/settings', params=params, body=body, **kwargs)

    def post_analytics_reporting_settings_dashboards_bulk_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/reporting/settings/dashboards/bulk/remove', params=params, body=body, **kwargs)

    def get_analytics_reporting_settings_dashboards_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/reporting/settings/dashboards/query', params=params, **kwargs)

    def post_analytics_reporting_settings_dashboards_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/reporting/settings/dashboards/query', params=params, body=body, **kwargs)

    def get_analytics_reporting_settings_user_dashboards(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/reporting/settings/users/{quote(str(user_id), safe='')}/dashboards", params=params, **kwargs)

    def post_analytics_resolutions_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/resolutions/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_resolutions_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/resolutions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_resolutions_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/resolutions/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_resolutions_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/resolutions/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_resolutions_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/resolutions/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_routing_activity_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/routing/activity/query', params=params, body=body, **kwargs)

    def post_analytics_summaries_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/summaries/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_summaries_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/summaries/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_summaries_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/summaries/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_summaries_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/summaries/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_summaries_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/summaries/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_surveys_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/surveys/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_surveys_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/surveys/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_surveys_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/surveys/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_surveys_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/surveys/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_surveys_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/surveys/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_taskmanagement_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/taskmanagement/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_taskmanagement_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/taskmanagement/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_taskmanagement_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/taskmanagement/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_taskmanagement_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/taskmanagement/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_taskmanagement_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/taskmanagement/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_taskmanagement_metrics_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/taskmanagement/metrics/query', params=params, body=body, **kwargs)

    def post_analytics_teams_activity_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/teams/activity/query', params=params, body=body, **kwargs)

    def post_analytics_transcripts_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/transcripts/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_transcripts_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/transcripts/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_transcripts_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/transcripts/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_transcripts_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/transcripts/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_transcripts_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/transcripts/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_users_activity_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/activity/query', params=params, body=body, **kwargs)

    def post_analytics_users_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/aggregates/jobs', params=params, body=body, **kwargs)

    def delete_analytics_users_aggregates_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/users/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_users_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/users/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_users_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/users/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_users_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/aggregates/query', params=params, body=body, **kwargs)

    def post_analytics_users_details_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/details/jobs', params=params, body=body, **kwargs)

    def get_analytics_users_details_jobs_availability(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/analytics/users/details/jobs/availability', params=params, **kwargs)

    def delete_analytics_users_details_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/analytics/users/details/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_analytics_users_details_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/users/details/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_analytics_users_details_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/analytics/users/details/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_analytics_users_details_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/details/query', params=params, body=body, **kwargs)

    def post_analytics_users_observations_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/analytics/users/observations/query', params=params, body=body, **kwargs)

    def get_architect_dependencytracking(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking', params=params, **kwargs)

    def get_architect_dependencytracking_build(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/build', params=params, **kwargs)

    def post_architect_dependencytracking_build(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/dependencytracking/build', params=params, body=body, **kwargs)

    def get_architect_dependencytracking_consumedresources(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/consumedresources', params=params, **kwargs)

    def get_architect_dependencytracking_consumingresources(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/consumingresources', params=params, **kwargs)

    def get_architect_dependencytracking_deletedresourceconsumers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/deletedresourceconsumers', params=params, **kwargs)

    def get_architect_dependencytracking_types(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/types', params=params, **kwargs)

    def get_architect_dependencytracking_type(self, type_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/dependencytracking/types/{quote(str(type_id), safe='')}", params=params, **kwargs)

    def get_architect_dependencytracking_updatedresourceconsumers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/dependencytracking/updatedresourceconsumers', params=params, **kwargs)

    def post_architect_emergencygroups(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/emergencygroups', params=params, body=body, **kwargs)

    def get_architect_emergencygroups_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/emergencygroups/divisionviews', params=params, **kwargs)

    def delete_architect_emergencygroup(self, emergency_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/emergencygroups/{quote(str(emergency_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_emergencygroup(self, emergency_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/emergencygroups/{quote(str(emergency_group_id), safe='')}", params=params, **kwargs)

    def put_architect_emergencygroup(self, emergency_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/emergencygroups/{quote(str(emergency_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_grammars(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/grammars', params=params, **kwargs)

    def post_architect_grammars(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/grammars', params=params, body=body, **kwargs)

    def delete_architect_grammar(self, grammar_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_grammar(self, grammar_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}", params=params, **kwargs)

    def patch_architect_grammar(self, grammar_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}", params=params, body=body, **kwargs)

    def post_architect_grammar_languages(self, grammar_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages", params=params, body=body, **kwargs)

    def delete_architect_grammar_language(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def get_architect_grammar_language(self, grammar_id, language_code, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}", params=params, **kwargs)

    def patch_architect_grammar_language(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def delete_architect_grammar_language_files_dtmf(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}/files/dtmf", params=params, body=body, **kwargs)

    def post_architect_grammar_language_files_dtmf(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}/files/dtmf", params=params, body=body, **kwargs)

    def delete_architect_grammar_language_files_voice(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}/files/voice", params=params, body=body, **kwargs)

    def post_architect_grammar_language_files_voice(self, grammar_id, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/grammars/{quote(str(grammar_id), safe='')}/languages/{quote(str(language_code), safe='')}/files/voice", params=params, body=body, **kwargs)

    def post_architect_ivrs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/ivrs', params=params, body=body, **kwargs)

    def get_architect_ivrs_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/ivrs/divisionviews', params=params, **kwargs)

    def delete_architect_ivr(self, ivr_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/ivrs/{quote(str(ivr_id), safe='')}", params=params, body=body, **kwargs)

    def put_architect_ivr(self, ivr_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/ivrs/{quote(str(ivr_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_ivr_identityresolution(self, ivr_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/ivrs/{quote(str(ivr_id), safe='')}/identityresolution", params=params, **kwargs)

    def put_architect_ivr_identityresolution(self, ivr_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/ivrs/{quote(str(ivr_id), safe='')}/identityresolution", params=params, body=body, **kwargs)

    def delete_architect_prompts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/architect/prompts', params=params, body=body, **kwargs)

    def delete_architect_prompt(self, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_prompt(self, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}", params=params, **kwargs)

    def put_architect_prompt(self, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}", params=params, body=body, **kwargs)

    def post_architect_prompt_history(self, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/history", params=params, body=body, **kwargs)

    def get_architect_prompt_history_history_id(self, history_id, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/history/{quote(str(history_id), safe='')}", params=params, **kwargs)

    def get_architect_prompt_resources(self, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/resources", params=params, **kwargs)

    def delete_architect_prompt_resource(self, language_code, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def get_architect_prompt_resource(self, language_code, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, **kwargs)

    def put_architect_prompt_resource(self, language_code, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def delete_architect_prompt_resource_audio(self, language_code, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/prompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}/audio", params=params, body=body, **kwargs)

    def post_architect_schedulegroups(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/schedulegroups', params=params, body=body, **kwargs)

    def get_architect_schedulegroups_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/schedulegroups/divisionviews', params=params, **kwargs)

    def delete_architect_schedulegroup(self, schedule_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/schedulegroups/{quote(str(schedule_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_schedulegroup(self, schedule_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/schedulegroups/{quote(str(schedule_group_id), safe='')}", params=params, **kwargs)

    def put_architect_schedulegroup(self, schedule_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/schedulegroups/{quote(str(schedule_group_id), safe='')}", params=params, body=body, **kwargs)

    def post_architect_schedules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/architect/schedules', params=params, body=body, **kwargs)

    def get_architect_schedules_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/architect/schedules/divisionviews', params=params, **kwargs)

    def delete_architect_schedule(self, schedule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/schedules/{quote(str(schedule_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_schedule(self, schedule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/schedules/{quote(str(schedule_id), safe='')}", params=params, **kwargs)

    def put_architect_schedule(self, schedule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/schedules/{quote(str(schedule_id), safe='')}", params=params, body=body, **kwargs)

    def get_architect_systemprompt(self, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}", params=params, **kwargs)

    def post_architect_systemprompt_history(self, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/history", params=params, body=body, **kwargs)

    def get_architect_systemprompt_history_history_id(self, history_id, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/history/{quote(str(history_id), safe='')}", params=params, **kwargs)

    def get_architect_systemprompt_resources(self, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/resources", params=params, **kwargs)

    def post_architect_systemprompt_resources(self, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/resources", params=params, body=body, **kwargs)

    def delete_architect_systemprompt_resource(self, language_code, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def get_architect_systemprompt_resource(self, language_code, prompt_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, **kwargs)

    def put_architect_systemprompt_resource(self, language_code, prompt_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/architect/systemprompts/{quote(str(prompt_id), safe='')}/resources/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def get_assistants(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/assistants', params=params, **kwargs)

    def post_assistants(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/assistants', params=params, body=body, **kwargs)

    def get_assistants_agentchecklists(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/assistants/agentchecklists', params=params, **kwargs)

    def post_assistants_agentchecklists(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/assistants/agentchecklists', params=params, body=body, **kwargs)

    def get_assistants_agentchecklists_languages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/assistants/agentchecklists/languages', params=params, **kwargs)

    def delete_assistants_agentchecklist(self, agent_checklist_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/assistants/agentchecklists/{quote(str(agent_checklist_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistants_agentchecklist(self, agent_checklist_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/agentchecklists/{quote(str(agent_checklist_id), safe='')}", params=params, **kwargs)

    def put_assistants_agentchecklist(self, agent_checklist_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/assistants/agentchecklists/{quote(str(agent_checklist_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistants_copilot_featuresupport(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/assistants/copilot/featuresupport', params=params, **kwargs)

    def get_assistants_queues(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/assistants/queues', params=params, **kwargs)

    def delete_assistant(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistant(self, assistant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}", params=params, **kwargs)

    def patch_assistant(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistant_copilot(self, assistant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/copilot", params=params, **kwargs)

    def put_assistant_copilot(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/copilot", params=params, body=body, **kwargs)

    def delete_assistant_queues(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues", params=params, body=body, **kwargs)

    def get_assistant_queues(self, assistant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues", params=params, **kwargs)

    def patch_assistant_queues(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues", params=params, body=body, **kwargs)

    def delete_assistant_queue(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistant_queue(self, assistant_id, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}", params=params, **kwargs)

    def put_assistant_queue(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}", params=params, body=body, **kwargs)

    def post_assistant_queue_users_bulk_add(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}/users/bulk/add", params=params, body=body, **kwargs)

    def post_assistant_queue_users_bulk_remove(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}/users/bulk/remove", params=params, body=body, **kwargs)

    def post_assistant_queue_users_jobs(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}/users/jobs", params=params, body=body, **kwargs)

    def get_assistant_queue_users_job(self, assistant_id, job_id, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}/users/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_assistant_queue_users_query(self, assistant_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/queues/{quote(str(queue_id), safe='')}/users/query", params=params, body=body, **kwargs)

    def get_assistant_variations(self, assistant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/variations", params=params, **kwargs)

    def post_assistant_variations(self, assistant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/variations", params=params, body=body, **kwargs)

    def delete_assistant_variation(self, assistant_id, variation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/variations/{quote(str(variation_id), safe='')}", params=params, body=body, **kwargs)

    def get_assistant_variation(self, assistant_id, variation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/variations/{quote(str(variation_id), safe='')}", params=params, **kwargs)

    def put_assistant_variation(self, assistant_id, variation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/assistants/{quote(str(assistant_id), safe='')}/variations/{quote(str(variation_id), safe='')}", params=params, body=body, **kwargs)

    def post_audits_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/audits/query', params=params, body=body, **kwargs)

    def post_audits_query_realtime_related(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/audits/query/realtime/related', params=params, body=body, **kwargs)

    def get_audits_query_realtime_servicemapping(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/audits/query/realtime/servicemapping', params=params, **kwargs)

    def get_audits_query_servicemapping(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/audits/query/servicemapping', params=params, **kwargs)

    def get_audits_query_transaction_id(self, transaction_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/audits/query/{quote(str(transaction_id), safe='')}", params=params, **kwargs)

    def get_audits_query_transaction_id_results(self, transaction_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/audits/query/{quote(str(transaction_id), safe='')}/results", params=params, **kwargs)

    def post_authorization_divisions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/authorization/divisions', params=params, body=body, **kwargs)

    def get_authorization_divisions_deleted(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisions/deleted', params=params, **kwargs)

    def get_authorization_divisions_home(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisions/home', params=params, **kwargs)

    def get_authorization_divisions_limit(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisions/limit', params=params, **kwargs)

    def get_authorization_divisions_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisions/query', params=params, **kwargs)

    def delete_authorization_division(self, division_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_division(self, division_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}", params=params, **kwargs)

    def put_authorization_division(self, division_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_division_grants(self, division_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}/grants", params=params, **kwargs)

    def post_authorization_division_object(self, division_id, object_type, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}/objects/{quote(str(object_type), safe='')}", params=params, body=body, **kwargs)

    def post_authorization_division_restore(self, division_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/divisions/{quote(str(division_id), safe='')}/restore", params=params, body=body, **kwargs)

    def get_authorization_divisionspermitted_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisionspermitted/me', params=params, **kwargs)

    def get_authorization_divisionspermitted_paged_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/divisionspermitted/paged/me', params=params, **kwargs)

    def get_authorization_divisionspermitted_paged_subject_id(self, subject_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/divisionspermitted/paged/{quote(str(subject_id), safe='')}", params=params, **kwargs)

    def get_authorization_policies(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/policies', params=params, **kwargs)

    def get_authorization_policies_subject_subject_id(self, subject_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/policies/subject/{quote(str(subject_id), safe='')}", params=params, **kwargs)

    def get_authorization_policies_targets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/policies/targets', params=params, **kwargs)

    def get_authorization_policies_target(self, target_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}", params=params, **kwargs)

    def post_authorization_policies_target(self, target_name, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}", params=params, body=body, **kwargs)

    def put_authorization_policies_target(self, target_name, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}", params=params, body=body, **kwargs)

    def delete_authorization_policies_target_subject_subject_id(self, subject_id, target_name, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}/subject/{quote(str(subject_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_policies_target_subject_subject_id(self, subject_id, target_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}/subject/{quote(str(subject_id), safe='')}", params=params, **kwargs)

    def post_authorization_policies_target_validate(self, target_name, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/policies/targets/{quote(str(target_name), safe='')}/validate", params=params, body=body, **kwargs)

    def get_authorization_policy(self, policy_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/policies/{quote(str(policy_id), safe='')}", params=params, **kwargs)

    def put_authorization_policy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/policies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_policy_attributes(self, policy_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/policies/{quote(str(policy_id), safe='')}/attributes", params=params, **kwargs)

    def post_authorization_policy_simulate(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/policies/{quote(str(policy_id), safe='')}/simulate", params=params, body=body, **kwargs)

    def get_authorization_products(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/products', params=params, **kwargs)

    def post_authorization_roles(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/authorization/roles', params=params, body=body, **kwargs)

    def post_authorization_roles_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/authorization/roles/default', params=params, body=body, **kwargs)

    def put_authorization_roles_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/authorization/roles/default', params=params, body=body, **kwargs)

    def get_authorization_roles_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/roles/settings', params=params, **kwargs)

    def put_authorization_roles_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/authorization/roles/settings', params=params, body=body, **kwargs)

    def get_authorization_role_comparedefault_right_role_id(self, left_role_id, right_role_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/roles/{quote(str(left_role_id), safe='')}/comparedefault/{quote(str(right_role_id), safe='')}", params=params, **kwargs)

    def post_authorization_role_comparedefault_right_role_id(self, left_role_id, right_role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/roles/{quote(str(left_role_id), safe='')}/comparedefault/{quote(str(right_role_id), safe='')}", params=params, body=body, **kwargs)

    def delete_authorization_role(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_role(self, role_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}", params=params, **kwargs)

    def patch_authorization_role(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def post_authorization_role(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def put_authorization_role(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def get_authorization_role_subjectgrants(self, role_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}/subjectgrants", params=params, **kwargs)

    def get_authorization_role_users(self, role_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}/users", params=params, **kwargs)

    def put_authorization_role_users_add(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}/users/add", params=params, body=body, **kwargs)

    def put_authorization_role_users_remove(self, role_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/authorization/roles/{quote(str(role_id), safe='')}/users/remove", params=params, body=body, **kwargs)

    def get_authorization_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/settings', params=params, **kwargs)

    def patch_authorization_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/authorization/settings', params=params, body=body, **kwargs)

    def get_authorization_subjects_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/subjects/me', params=params, **kwargs)

    def get_authorization_subjects_rolecounts(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/authorization/subjects/rolecounts', params=params, **kwargs)

    def get_authorization_subject(self, subject_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/authorization/subjects/{quote(str(subject_id), safe='')}", params=params, **kwargs)

    def post_authorization_subject_bulkremove(self, subject_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/subjects/{quote(str(subject_id), safe='')}/bulkremove", params=params, body=body, **kwargs)

    def post_authorization_subject_bulkreplace(self, subject_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/subjects/{quote(str(subject_id), safe='')}/bulkreplace", params=params, body=body, **kwargs)

    def delete_authorization_subject_division_role(self, division_id, role_id, subject_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/authorization/subjects/{quote(str(subject_id), safe='')}/divisions/{quote(str(division_id), safe='')}/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def post_authorization_subject_division_role(self, division_id, role_id, subject_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/authorization/subjects/{quote(str(subject_id), safe='')}/divisions/{quote(str(division_id), safe='')}/roles/{quote(str(role_id), safe='')}", params=params, body=body, **kwargs)

    def get_billing_reports_billableusage(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/billing/reports/billableusage', params=params, **kwargs)

    def get_billing_trusteebillingoverview_trustor_org_id(self, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/billing/trusteebillingoverview/{quote(str(trustor_org_id), safe='')}", params=params, **kwargs)

    def get_businessrules_decisiontables(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/businessrules/decisiontables', params=params, **kwargs)

    def post_businessrules_decisiontables(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/businessrules/decisiontables', params=params, body=body, **kwargs)

    def get_businessrules_decisiontables_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/businessrules/decisiontables/search', params=params, **kwargs)

    def delete_businessrules_decisiontable(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable(self, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}", params=params, **kwargs)

    def patch_businessrules_decisiontable(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_execute(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/execute", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_exports(self, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/exports", params=params, **kwargs)

    def post_businessrules_decisiontable_exports(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/exports", params=params, body=body, **kwargs)

    def delete_businessrules_decisiontable_export(self, export_job_id, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/exports/{quote(str(export_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_export(self, export_job_id, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/exports/{quote(str(export_job_id), safe='')}", params=params, **kwargs)

    def get_businessrules_decisiontable_imports(self, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/imports", params=params, **kwargs)

    def post_businessrules_decisiontable_imports(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/imports", params=params, body=body, **kwargs)

    def delete_businessrules_decisiontable_import(self, import_job_id, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/imports/{quote(str(import_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_import(self, import_job_id, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/imports/{quote(str(import_job_id), safe='')}", params=params, **kwargs)

    def patch_businessrules_decisiontable_import(self, import_job_id, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/imports/{quote(str(import_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_versions(self, table_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions", params=params, **kwargs)

    def post_businessrules_decisiontable_versions(self, table_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions", params=params, body=body, **kwargs)

    def delete_businessrules_decisiontable_version(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_version(self, table_id, table_version, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}", params=params, **kwargs)

    def patch_businessrules_decisiontable_version(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_copy(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/copy", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_execute(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/execute", params=params, body=body, **kwargs)

    def put_businessrules_decisiontable_version_publish(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/publish", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_rollback(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rollback", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_version_rows(self, table_id, table_version, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows", params=params, **kwargs)

    def post_businessrules_decisiontable_version_rows(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_rows_bulk_add(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/bulk/add", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_rows_bulk_remove(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/bulk/remove", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_rows_bulk_update(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/bulk/update", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_rows_search(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/search", params=params, body=body, **kwargs)

    def delete_businessrules_decisiontable_version_row(self, row_id, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/{quote(str(row_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_decisiontable_version_row(self, row_id, table_id, table_version, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/{quote(str(row_id), safe='')}", params=params, **kwargs)

    def put_businessrules_decisiontable_version_row(self, row_id, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/rows/{quote(str(row_id), safe='')}", params=params, body=body, **kwargs)

    def delete_businessrules_decisiontable_version_snapshot(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/snapshot", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_snapshot(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/snapshot", params=params, body=body, **kwargs)

    def post_businessrules_decisiontable_version_sync(self, table_id, table_version, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/businessrules/decisiontables/{quote(str(table_id), safe='')}/versions/{quote(str(table_version), safe='')}/sync", params=params, body=body, **kwargs)

    def get_businessrules_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/businessrules/schemas', params=params, **kwargs)

    def post_businessrules_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/businessrules/schemas', params=params, body=body, **kwargs)

    def get_businessrules_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/businessrules/schemas/coretypes', params=params, **kwargs)

    def get_businessrules_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def delete_businessrules_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/businessrules/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_businessrules_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/businessrules/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_businessrules_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_businessrules_schema_version(self, schema_id, schema_version, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/businessrules/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(schema_version), safe='')}", params=params, **kwargs)

    def get_carrierservices_integrations_emergencylocations_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/carrierservices/integrations/emergencylocations/me', params=params, **kwargs)

    def post_carrierservices_integrations_emergencylocations_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/carrierservices/integrations/emergencylocations/me', params=params, body=body, **kwargs)

    def get_casemanagement_caseplans(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/casemanagement/caseplans', params=params, **kwargs)

    def post_casemanagement_caseplans(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/casemanagement/caseplans', params=params, body=body, **kwargs)

    def post_casemanagement_caseplans_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/casemanagement/caseplans/query', params=params, body=body, **kwargs)

    def delete_casemanagement_caseplan(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}", params=params, body=body, **kwargs)

    def get_casemanagement_caseplan(self, caseplan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}", params=params, **kwargs)

    def patch_casemanagement_caseplan(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}", params=params, body=body, **kwargs)

    def post_casemanagement_caseplan_dataschemas(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/dataschemas", params=params, body=body, **kwargs)

    def delete_casemanagement_caseplan_dataschema(self, caseplan_id, schema_key_name, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/dataschemas/{quote(str(schema_key_name), safe='')}", params=params, body=body, **kwargs)

    def put_casemanagement_caseplan_dataschema(self, caseplan_id, schema_key_name, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/dataschemas/{quote(str(schema_key_name), safe='')}", params=params, body=body, **kwargs)

    def put_casemanagement_caseplan_intakesettings(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/intakesettings", params=params, body=body, **kwargs)

    def post_casemanagement_caseplan_publish(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/publish", params=params, body=body, **kwargs)

    def post_casemanagement_caseplan_stageplans(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/stageplans", params=params, body=body, **kwargs)

    def delete_casemanagement_caseplan_stageplan(self, caseplan_id, stageplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}", params=params, body=body, **kwargs)

    def patch_casemanagement_caseplan_stageplan(self, caseplan_id, stageplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}", params=params, body=body, **kwargs)

    def post_casemanagement_caseplan_stageplan_reposition(self, caseplan_id, stageplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}/reposition", params=params, body=body, **kwargs)

    def patch_casemanagement_caseplan_stageplan_stepplan(self, caseplan_id, stageplan_id, stepplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}/stepplans/{quote(str(stepplan_id), safe='')}", params=params, body=body, **kwargs)

    def post_casemanagement_caseplan_versions(self, caseplan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions", params=params, body=body, **kwargs)

    def get_casemanagement_caseplan_version(self, caseplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_caseplan_version_dataschemas(self, caseplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/dataschemas", params=params, **kwargs)

    def get_casemanagement_caseplan_version_intakesettings(self, caseplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/intakesettings", params=params, **kwargs)

    def get_casemanagement_caseplan_version_stageplans(self, caseplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/stageplans", params=params, **kwargs)

    def get_casemanagement_caseplan_version_stageplan(self, caseplan_id, stageplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_caseplan_version_stageplan_stepplans(self, caseplan_id, stageplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}/stepplans", params=params, **kwargs)

    def get_casemanagement_caseplan_version_stageplan_stepplan(self, caseplan_id, stageplan_id, stepplan_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/caseplans/{quote(str(caseplan_id), safe='')}/versions/{quote(str(version_id), safe='')}/stageplans/{quote(str(stageplan_id), safe='')}/stepplans/{quote(str(stepplan_id), safe='')}", params=params, **kwargs)

    def post_casemanagement_cases(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/casemanagement/cases', params=params, body=body, **kwargs)

    def post_casemanagement_cases_associations_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/casemanagement/cases/associations/query', params=params, body=body, **kwargs)

    def get_casemanagement_cases_externalcontact(self, external_contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/externalcontacts/{quote(str(external_contact_id), safe='')}", params=params, **kwargs)

    def post_casemanagement_cases_query_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/casemanagement/cases/query/jobs', params=params, body=body, **kwargs)

    def get_casemanagement_cases_query_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_cases_query_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/query/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def get_casemanagement_cases_reference(self, reference_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/references/{quote(str(reference_id), safe='')}", params=params, **kwargs)

    def delete_casemanagement_case(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}", params=params, body=body, **kwargs)

    def get_casemanagement_case(self, case_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_case_associations(self, case_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/associations", params=params, **kwargs)

    def post_casemanagement_case_associations(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/associations", params=params, body=body, **kwargs)

    def get_casemanagement_case_association(self, association_id, case_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/associations/{quote(str(association_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_case_comments(self, case_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/comments", params=params, **kwargs)

    def post_casemanagement_case_comments(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/comments", params=params, body=body, **kwargs)

    def delete_casemanagement_case_comments_me_comment_id(self, case_id, comment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/comments/me/{quote(str(comment_id), safe='')}", params=params, body=body, **kwargs)

    def get_casemanagement_case_comment(self, case_id, comment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/comments/{quote(str(comment_id), safe='')}", params=params, **kwargs)

    def patch_casemanagement_case_datedue(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/datedue", params=params, body=body, **kwargs)

    def patch_casemanagement_case_owner(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/owner", params=params, body=body, **kwargs)

    def patch_casemanagement_case_priority(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/priority", params=params, body=body, **kwargs)

    def get_casemanagement_case_stages(self, case_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/stages", params=params, **kwargs)

    def get_casemanagement_case_stage(self, case_id, stage_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/stages/{quote(str(stage_id), safe='')}", params=params, **kwargs)

    def get_casemanagement_case_stage_steps(self, case_id, stage_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/stages/{quote(str(stage_id), safe='')}/steps", params=params, **kwargs)

    def get_casemanagement_case_stage_step(self, case_id, stage_id, step_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/stages/{quote(str(stage_id), safe='')}/steps/{quote(str(step_id), safe='')}", params=params, **kwargs)

    def patch_casemanagement_case_summary(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/summary", params=params, body=body, **kwargs)

    def post_casemanagement_case_terminate_jobs(self, case_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/terminate/jobs", params=params, body=body, **kwargs)

    def get_casemanagement_case_terminate_job(self, case_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/casemanagement/cases/{quote(str(case_id), safe='')}/terminate/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_certificate_details(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/certificate/details', params=params, body=body, **kwargs)

    def get_chats_message(self, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/messages/{quote(str(message_id), safe='')}", params=params, **kwargs)

    def put_chats_message_reactions(self, message_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/chats/messages/{quote(str(message_id), safe='')}/reactions", params=params, body=body, **kwargs)

    def post_chats_rooms(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/chats/rooms', params=params, body=body, **kwargs)

    def get_chats_room(self, room_jid, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}", params=params, **kwargs)

    def patch_chats_room(self, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}", params=params, body=body, **kwargs)

    def get_chats_room_messages(self, room_jid, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages", params=params, **kwargs)

    def post_chats_room_messages(self, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages", params=params, body=body, **kwargs)

    def post_chats_room_messages_pins(self, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages/pins", params=params, body=body, **kwargs)

    def delete_chats_room_messages_pin(self, pinned_message_id, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages/pins/{quote(str(pinned_message_id), safe='')}", params=params, body=body, **kwargs)

    def get_chats_room_message(self, message_ids, room_jid, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages/{quote(str(message_ids), safe='')}", params=params, **kwargs)

    def delete_chats_room_message(self, message_id, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def patch_chats_room_message(self, message_id, room_jid, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def get_chats_room_participants(self, room_jid, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/participants", params=params, **kwargs)

    def get_chats_room_participant(self, participant_jid, room_jid, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/participants/{quote(str(participant_jid), safe='')}", params=params, **kwargs)

    def delete_chats_room_participant(self, room_jid, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/participants/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def post_chats_room_participant(self, room_jid, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/chats/rooms/{quote(str(room_jid), safe='')}/participants/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_chats_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/chats/settings', params=params, **kwargs)

    def patch_chats_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/chats/settings', params=params, body=body, **kwargs)

    def put_chats_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/chats/settings', params=params, body=body, **kwargs)

    def get_chats_thread_messages(self, thread_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/threads/{quote(str(thread_id), safe='')}/messages", params=params, **kwargs)

    def delete_chats_users_me_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/chats/users/me/settings', params=params, body=body, **kwargs)

    def get_chats_users_me_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/chats/users/me/settings', params=params, **kwargs)

    def patch_chats_users_me_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/chats/users/me/settings', params=params, body=body, **kwargs)

    def post_chats_users_me_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/chats/users/me/settings', params=params, body=body, **kwargs)

    def get_chats_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def get_chats_user_messages(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages", params=params, **kwargs)

    def post_chats_user_messages(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages", params=params, body=body, **kwargs)

    def post_chats_user_messages_pins(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages/pins", params=params, body=body, **kwargs)

    def delete_chats_user_messages_pin(self, pinned_message_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages/pins/{quote(str(pinned_message_id), safe='')}", params=params, body=body, **kwargs)

    def get_chats_user_message(self, message_ids, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages/{quote(str(message_ids), safe='')}", params=params, **kwargs)

    def delete_chats_user_message(self, message_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def patch_chats_user_message(self, message_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def get_chats_user_settings(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/settings", params=params, **kwargs)

    def patch_chats_user_settings(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/chats/users/{quote(str(user_id), safe='')}/settings", params=params, body=body, **kwargs)

    def get_coaching_appointments(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/coaching/appointments', params=params, **kwargs)

    def post_coaching_appointments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/coaching/appointments', params=params, body=body, **kwargs)

    def post_coaching_appointments_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/coaching/appointments/aggregates/query', params=params, body=body, **kwargs)

    def get_coaching_appointments_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/coaching/appointments/me', params=params, **kwargs)

    def delete_coaching_appointment(self, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}", params=params, body=body, **kwargs)

    def get_coaching_appointment(self, appointment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}", params=params, **kwargs)

    def patch_coaching_appointment(self, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}", params=params, body=body, **kwargs)

    def get_coaching_appointment_annotations(self, appointment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/annotations", params=params, **kwargs)

    def post_coaching_appointment_annotations(self, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/annotations", params=params, body=body, **kwargs)

    def delete_coaching_appointment_annotation(self, annotation_id, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, body=body, **kwargs)

    def get_coaching_appointment_annotation(self, annotation_id, appointment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, **kwargs)

    def patch_coaching_appointment_annotation(self, annotation_id, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, body=body, **kwargs)

    def post_coaching_appointment_conversations(self, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/conversations", params=params, body=body, **kwargs)

    def patch_coaching_appointment_status(self, appointment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/status", params=params, body=body, **kwargs)

    def get_coaching_appointment_statuses(self, appointment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/appointments/{quote(str(appointment_id), safe='')}/statuses", params=params, **kwargs)

    def get_coaching_notifications(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/coaching/notifications', params=params, **kwargs)

    def get_coaching_notification(self, notification_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/notifications/{quote(str(notification_id), safe='')}", params=params, **kwargs)

    def patch_coaching_notification(self, notification_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/coaching/notifications/{quote(str(notification_id), safe='')}", params=params, body=body, **kwargs)

    def post_coaching_scheduleslots_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/coaching/scheduleslots/jobs', params=params, body=body, **kwargs)

    def get_coaching_scheduleslots_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/coaching/scheduleslots/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_coaching_scheduleslots_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/coaching/scheduleslots/query', params=params, body=body, **kwargs)

    def get_contentmanagement_documents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/documents', params=params, **kwargs)

    def post_contentmanagement_documents(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/contentmanagement/documents', params=params, body=body, **kwargs)

    def delete_contentmanagement_document(self, document_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_document(self, document_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/documents/{quote(str(document_id), safe='')}", params=params, **kwargs)

    def post_contentmanagement_document(self, document_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/contentmanagement/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_document_content(self, document_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/documents/{quote(str(document_id), safe='')}/content", params=params, **kwargs)

    def post_contentmanagement_document_content(self, document_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/contentmanagement/documents/{quote(str(document_id), safe='')}/content", params=params, body=body, **kwargs)

    def get_contentmanagement_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/query', params=params, **kwargs)

    def post_contentmanagement_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/contentmanagement/query', params=params, body=body, **kwargs)

    def get_contentmanagement_securityprofiles(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/securityprofiles', params=params, **kwargs)

    def get_contentmanagement_securityprofile(self, security_profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/securityprofiles/{quote(str(security_profile_id), safe='')}", params=params, **kwargs)

    def get_contentmanagement_shared_shared_id(self, shared_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/shared/{quote(str(shared_id), safe='')}", params=params, **kwargs)

    def get_contentmanagement_shares(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/shares', params=params, **kwargs)

    def post_contentmanagement_shares(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/contentmanagement/shares', params=params, body=body, **kwargs)

    def delete_contentmanagement_share(self, share_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/shares/{quote(str(share_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_share(self, share_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/shares/{quote(str(share_id), safe='')}", params=params, **kwargs)

    def get_contentmanagement_status(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/status', params=params, **kwargs)

    def delete_contentmanagement_status_status_id(self, status_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/status/{quote(str(status_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_status_status_id(self, status_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/status/{quote(str(status_id), safe='')}", params=params, **kwargs)

    def get_contentmanagement_usage(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/usage', params=params, **kwargs)

    def get_contentmanagement_workspaces(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/contentmanagement/workspaces', params=params, **kwargs)

    def post_contentmanagement_workspaces(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/contentmanagement/workspaces', params=params, body=body, **kwargs)

    def delete_contentmanagement_workspace(self, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_workspace(self, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}", params=params, **kwargs)

    def put_contentmanagement_workspace(self, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_workspace_documents(self, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/documents", params=params, **kwargs)

    def get_contentmanagement_workspace_members(self, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/members", params=params, **kwargs)

    def delete_contentmanagement_workspace_member(self, member_id, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/members/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_workspace_member(self, member_id, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/members/{quote(str(member_id), safe='')}", params=params, **kwargs)

    def put_contentmanagement_workspace_member(self, member_id, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/members/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_workspace_tagvalues(self, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues", params=params, **kwargs)

    def post_contentmanagement_workspace_tagvalues(self, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues", params=params, body=body, **kwargs)

    def post_contentmanagement_workspace_tagvalues_query(self, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues/query", params=params, body=body, **kwargs)

    def delete_contentmanagement_workspace_tagvalue(self, tag_id, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues/{quote(str(tag_id), safe='')}", params=params, body=body, **kwargs)

    def get_contentmanagement_workspace_tagvalue(self, tag_id, workspace_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues/{quote(str(tag_id), safe='')}", params=params, **kwargs)

    def put_contentmanagement_workspace_tagvalue(self, tag_id, workspace_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/contentmanagement/workspaces/{quote(str(workspace_id), safe='')}/tagvalues/{quote(str(tag_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations', params=params, **kwargs)

    def patch_conversations_aftercallwork_conversation_id_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/aftercallwork/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_callbacks(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/callbacks', params=params, **kwargs)

    def patch_conversations_callbacks(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/conversations/callbacks', params=params, body=body, **kwargs)

    def post_conversations_callbacks(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/callbacks', params=params, body=body, **kwargs)

    def post_conversations_callbacks_bulk_disconnect(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/callbacks/bulk/disconnect', params=params, body=body, **kwargs)

    def post_conversations_callbacks_bulk_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/callbacks/bulk/update', params=params, body=body, **kwargs)

    def get_conversations_callback(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def patch_conversations_callback(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_callback_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_callback_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def patch_conversations_callback_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_callback_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_callback_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def post_conversations_callback_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def get_conversations_callback_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversations_callback_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def put_conversations_callback_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/callbacks/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversations_calls(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/calls', params=params, **kwargs)

    def post_conversations_calls(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/calls', params=params, body=body, **kwargs)

    def get_conversations_calls_history(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/calls/history', params=params, **kwargs)

    def get_conversations_calls_maximumconferenceparties(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/calls/maximumconferenceparties', params=params, **kwargs)

    def post_conversations_calls_user_user_id(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/user/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_call(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def patch_conversations_call(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_call(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_call_conference(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/conference", params=params, body=body, **kwargs)

    def post_conversations_call_participants(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants", params=params, body=body, **kwargs)

    def post_conversations_call_participants_user_user_id(self, conversation_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/user/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_call_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_call_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def post_conversations_call_participant_barge(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/barge", params=params, body=body, **kwargs)

    def post_conversations_call_participant_coach(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/coach", params=params, body=body, **kwargs)

    def patch_conversations_call_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def delete_conversations_call_participant_communication_postflowaction(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/postflowaction", params=params, body=body, **kwargs)

    def patch_conversations_call_participant_communication_postflowaction(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/postflowaction", params=params, body=body, **kwargs)

    def post_conversations_call_participant_communication_summaries(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/summaries", params=params, body=body, **kwargs)

    def put_conversations_call_participant_communication_uuidata(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/uuidata", params=params, body=body, **kwargs)

    def get_conversations_call_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_call_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def delete_conversations_call_participant_consult(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult", params=params, body=body, **kwargs)

    def patch_conversations_call_participant_consult(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult", params=params, body=body, **kwargs)

    def post_conversations_call_participant_consult(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult", params=params, body=body, **kwargs)

    def post_conversations_call_participant_consult_agent(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult/agent", params=params, body=body, **kwargs)

    def post_conversations_call_participant_consult_contact_external(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult/contact/external", params=params, body=body, **kwargs)

    def post_conversations_call_participant_consult_external(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult/external", params=params, body=body, **kwargs)

    def post_conversations_call_participant_consult_queue(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/consult/queue", params=params, body=body, **kwargs)

    def post_conversations_call_participant_monitor(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/monitor", params=params, body=body, **kwargs)

    def post_conversations_call_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def post_conversations_call_participant_snippet_record(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/snippet/record", params=params, body=body, **kwargs)

    def patch_conversations_call_participant_user_user_id(self, conversation_id, participant_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/user/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_call_participant_voice_consult(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/voice/consult", params=params, body=body, **kwargs)

    def get_conversations_call_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversations_call_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def put_conversations_call_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/calls/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversations_cobrowsesessions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/cobrowsesessions', params=params, **kwargs)

    def get_conversations_cobrowsesession(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def patch_conversations_cobrowsesession(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_cobrowsesession_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_cobrowsesession_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def patch_conversations_cobrowsesession_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_cobrowsesession_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_cobrowsesession_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def post_conversations_cobrowsesession_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def get_conversations_cobrowsesession_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversations_cobrowsesession_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def put_conversations_cobrowsesession_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/cobrowsesessions/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversations_customattributes_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/customattributes/schemas', params=params, **kwargs)

    def post_conversations_customattributes_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/customattributes/schemas', params=params, body=body, **kwargs)

    def get_conversations_customattributes_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/customattributes/schemas/coretypes', params=params, **kwargs)

    def get_conversations_customattributes_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/customattributes/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_conversations_customattributes_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/customattributes/schemas/limits', params=params, **kwargs)

    def get_conversations_customattributes_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/customattributes/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_conversations_customattributes_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/customattributes/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_customattributes_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/customattributes/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_conversations_customattributes_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/customattributes/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def post_conversations_customattributes_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/customattributes/search', params=params, body=body, **kwargs)

    def get_conversations_emails(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/emails', params=params, **kwargs)

    def post_conversations_emails(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/emails', params=params, body=body, **kwargs)

    def post_conversations_emails_agentless(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/emails/agentless', params=params, body=body, **kwargs)

    def get_conversations_email(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def patch_conversations_email(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_email_inboundmessages(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/inboundmessages", params=params, body=body, **kwargs)

    def get_conversations_email_messages(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages", params=params, **kwargs)

    def post_conversations_email_messages(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages", params=params, body=body, **kwargs)

    def get_conversations_email_messages_draft(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft", params=params, **kwargs)

    def patch_conversations_email_messages_draft(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft", params=params, body=body, **kwargs)

    def put_conversations_email_messages_draft(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft", params=params, body=body, **kwargs)

    def post_conversations_email_messages_draft_attachments_copy(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft/attachments/copy", params=params, body=body, **kwargs)

    def post_conversations_email_messages_draft_attachments_uploads(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft/attachments/uploads", params=params, body=body, **kwargs)

    def delete_conversations_email_messages_draft_attachment(self, attachment_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/draft/attachments/{quote(str(attachment_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_email_message(self, conversation_id, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, **kwargs)

    def patch_conversations_email_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_email_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def patch_conversations_email_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_email_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_email_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def patch_conversations_email_participant_parkingstate(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/parkingstate", params=params, body=body, **kwargs)

    def post_conversations_email_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def get_conversations_email_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversations_email_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def post_conversations_email_reconnect(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/reconnect", params=params, body=body, **kwargs)

    def put_conversations_email_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversations_email_settings(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/emails/{quote(str(conversation_id), safe='')}/settings", params=params, **kwargs)

    def post_conversations_faxes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/faxes', params=params, body=body, **kwargs)

    def get_conversations_internalmessages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/internalmessages', params=params, **kwargs)

    def get_conversations_internalmessage(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/internalmessages/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def get_conversations_keyconfigurations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/keyconfigurations', params=params, **kwargs)

    def post_conversations_keyconfigurations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/keyconfigurations', params=params, body=body, **kwargs)

    def post_conversations_keyconfigurations_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/keyconfigurations/validate', params=params, body=body, **kwargs)

    def get_conversations_keyconfiguration(self, keyconfigurations_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/keyconfigurations/{quote(str(keyconfigurations_id), safe='')}", params=params, **kwargs)

    def put_conversations_keyconfiguration(self, keyconfigurations_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/keyconfigurations/{quote(str(keyconfigurations_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messages', params=params, **kwargs)

    def post_conversations_messages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messages', params=params, body=body, **kwargs)

    def post_conversations_messages_agentless(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messages/agentless', params=params, body=body, **kwargs)

    def get_conversations_messages_cachedmedia(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messages/cachedmedia', params=params, **kwargs)

    def delete_conversations_messages_cachedmedia_cached_media_item_id(self, cached_media_item_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messages/cachedmedia/{quote(str(cached_media_item_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messages_cachedmedia_cached_media_item_id(self, cached_media_item_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/cachedmedia/{quote(str(cached_media_item_id), safe='')}", params=params, **kwargs)

    def post_conversations_messages_inbound_open(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messages/inbound/open', params=params, body=body, **kwargs)

    def get_conversations_message(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def patch_conversations_message(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_message_communication_messages(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/messages", params=params, body=body, **kwargs)

    def get_conversations_message_communication_messages_media(self, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/messages/media", params=params, **kwargs)

    def post_conversations_message_communication_messages_media(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/messages/media", params=params, body=body, **kwargs)

    def post_conversations_message_communication_messages_media_uploads(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/messages/media/uploads", params=params, body=body, **kwargs)

    def get_conversations_message_communication_messages_media_media_id(self, communication_id, conversation_id, media_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/messages/media/{quote(str(media_id), safe='')}", params=params, **kwargs)

    def post_conversations_message_communication_socialmedia_messages(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/socialmedia/messages", params=params, body=body, **kwargs)

    def post_conversations_message_communication_typing(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/typing", params=params, body=body, **kwargs)

    def post_conversations_message_messages_bulk(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/messages/bulk", params=params, body=body, **kwargs)

    def get_conversations_message_message(self, conversation_id, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/messages/{quote(str(message_id), safe='')}", params=params, **kwargs)

    def patch_conversations_message_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversations_message_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def patch_conversations_message_participant_communication(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_message_participant_communication_summaries(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/summaries", params=params, body=body, **kwargs)

    def get_conversations_message_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_message_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def post_conversations_message_participant_monitor(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/monitor", params=params, body=body, **kwargs)

    def patch_conversations_message_participant_parkingstate(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/parkingstate", params=params, body=body, **kwargs)

    def post_conversations_message_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def post_conversations_message_participant_takeover(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/takeover", params=params, body=body, **kwargs)

    def get_conversations_message_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversations_message_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def put_conversations_message_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messages/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def post_conversations_message_inbound_open_event(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(integration_id), safe='')}/inbound/open/event", params=params, body=body, **kwargs)

    def post_conversations_message_inbound_open_message(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(integration_id), safe='')}/inbound/open/message", params=params, body=body, **kwargs)

    def post_conversations_message_inbound_open_receipt(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(integration_id), safe='')}/inbound/open/receipt", params=params, body=body, **kwargs)

    def post_conversations_message_inbound_open_structured_response(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/messages/{quote(str(integration_id), safe='')}/inbound/open/structured/response", params=params, body=body, **kwargs)

    def get_conversations_message_details(self, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messages/{quote(str(message_id), safe='')}/details", params=params, **kwargs)

    def get_conversations_messaging_facebook_app(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/facebook/app', params=params, **kwargs)

    def get_conversations_messaging_facebook_permissions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/facebook/permissions', params=params, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_apple_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/apple/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_apple_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/apple/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_facebook_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/facebook/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_facebook_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/facebook/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_instagram_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/instagram/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_instagram_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/instagram/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_open_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/open/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_open_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/open/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_twitter_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/twitter/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_twitter_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/twitter/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_identityresolution_integrations_whatsapp_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/identityresolution/integrations/whatsapp/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def put_conversations_messaging_identityresolution_integrations_whatsapp_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/messaging/identityresolution/integrations/whatsapp/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations', params=params, **kwargs)

    def get_conversations_messaging_integrations_apple(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/apple', params=params, **kwargs)

    def post_conversations_messaging_integrations_apple(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/apple', params=params, body=body, **kwargs)

    def delete_conversations_messaging_integrations_apple_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/apple/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_apple_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/apple/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_apple_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/apple/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_facebook(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/facebook', params=params, **kwargs)

    def post_conversations_messaging_integrations_facebook(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/facebook', params=params, body=body, **kwargs)

    def delete_conversations_messaging_integrations_facebook_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/facebook/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_facebook_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/facebook/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_facebook_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/facebook/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_instagram(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/instagram', params=params, **kwargs)

    def post_conversations_messaging_integrations_instagram(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/instagram', params=params, body=body, **kwargs)

    def delete_conversations_messaging_integrations_instagram_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/instagram/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_instagram_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/instagram/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_instagram_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/instagram/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_open(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/open', params=params, **kwargs)

    def post_conversations_messaging_integrations_open(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/open', params=params, body=body, **kwargs)

    def delete_conversations_messaging_integrations_open_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/open/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_open_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/open/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_open_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/open/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_twitter(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/twitter', params=params, **kwargs)

    def post_conversations_messaging_integrations_twitter(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/twitter', params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_twitter_oauth_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/twitter/oauth/settings', params=params, **kwargs)

    def delete_conversations_messaging_integrations_twitter_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/twitter/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_twitter_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/twitter/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_twitter_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/twitter/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_whatsapp(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/integrations/whatsapp', params=params, **kwargs)

    def post_conversations_messaging_integrations_whatsapp(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/whatsapp', params=params, body=body, **kwargs)

    def post_conversations_messaging_integrations_whatsapp_embeddedsignup(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/integrations/whatsapp/embeddedsignup', params=params, body=body, **kwargs)

    def patch_conversations_messaging_integrations_whatsapp_embeddedsignup_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/whatsapp/embeddedsignup/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def delete_conversations_messaging_integrations_whatsapp_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/integrations/whatsapp/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integrations_whatsapp_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/whatsapp/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_integrations_whatsapp_integration_id(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/integrations/whatsapp/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_integration_twitter_oauth_settings(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/integrations/{quote(str(integration_id), safe='')}/twitter/oauth/settings", params=params, **kwargs)

    def get_conversations_messaging_oauth_apple_callback(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/oauth/apple/callback', params=params, **kwargs)

    def get_conversations_messaging_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/settings', params=params, **kwargs)

    def post_conversations_messaging_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/settings', params=params, body=body, **kwargs)

    def delete_conversations_messaging_settings_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/conversations/messaging/settings/default', params=params, body=body, **kwargs)

    def get_conversations_messaging_settings_default(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/settings/default', params=params, **kwargs)

    def put_conversations_messaging_settings_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/conversations/messaging/settings/default', params=params, body=body, **kwargs)

    def delete_conversations_messaging_setting(self, message_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_setting(self, message_setting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_setting(self, message_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_supportedcontent(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/supportedcontent', params=params, **kwargs)

    def post_conversations_messaging_supportedcontent(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/messaging/supportedcontent', params=params, body=body, **kwargs)

    def get_conversations_messaging_supportedcontent_default(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/supportedcontent/default', params=params, **kwargs)

    def put_conversations_messaging_supportedcontent_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/conversations/messaging/supportedcontent/default', params=params, body=body, **kwargs)

    def delete_conversations_messaging_supportedcontent_supported_content_id(self, supported_content_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_supportedcontent_supported_content_id(self, supported_content_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, **kwargs)

    def patch_conversations_messaging_supportedcontent_supported_content_id(self, supported_content_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_messaging_threadingtimeline(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/messaging/threadingtimeline', params=params, **kwargs)

    def put_conversations_messaging_threadingtimeline(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/conversations/messaging/threadingtimeline', params=params, body=body, **kwargs)

    def get_conversations_screenshare_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/screenshares/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_screenshare_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/screenshares/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def put_conversations_screenshare_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/screenshares/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversations_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/settings', params=params, **kwargs)

    def patch_conversations_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/conversations/settings', params=params, body=body, **kwargs)

    def get_conversations_social_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/socials/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_social_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/socials/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def put_conversations_social_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/socials/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def post_conversations_summaries_preview(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/summaries/preview', params=params, body=body, **kwargs)

    def get_conversations_summaries_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/conversations/summaries/settings', params=params, **kwargs)

    def post_conversations_summaries_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/summaries/settings', params=params, body=body, **kwargs)

    def delete_conversations_summaries_setting(self, summary_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/summaries/settings/{quote(str(summary_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversations_summaries_setting(self, summary_setting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/summaries/settings/{quote(str(summary_setting_id), safe='')}", params=params, **kwargs)

    def put_conversations_summaries_setting(self, summary_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/summaries/settings/{quote(str(summary_setting_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversations_videos_meetings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/conversations/videos/meetings', params=params, body=body, **kwargs)

    def get_conversations_videos_meeting(self, meeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/videos/meetings/{quote(str(meeting_id), safe='')}", params=params, **kwargs)

    def get_conversations_video_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/videos/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, **kwargs)

    def post_conversations_video_participant_communication_wrapup(self, communication_id, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/videos/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/communications/{quote(str(communication_id), safe='')}/wrapup", params=params, body=body, **kwargs)

    def put_conversations_video_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/videos/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def delete_conversation(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversation_assign(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/assign", params=params, body=body, **kwargs)

    def post_conversation_barge(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/barge", params=params, body=body, **kwargs)

    def post_conversation_cobrowse(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/cobrowse", params=params, body=body, **kwargs)

    def get_conversation_communication_agentchecklists(self, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists", params=params, **kwargs)

    def post_conversation_communication_agentchecklists_finalize(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/finalize", params=params, body=body, **kwargs)

    def get_conversation_communication_agentchecklist(self, agent_checklist_id, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/{quote(str(agent_checklist_id), safe='')}", params=params, **kwargs)

    def post_conversation_communication_agentchecklist(self, agent_checklist_id, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/{quote(str(agent_checklist_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversation_communication_agentchecklist_agentaction(self, agent_checklist_id, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/{quote(str(agent_checklist_id), safe='')}/agentaction", params=params, body=body, **kwargs)

    def post_conversation_communication_agentchecklist_jobs(self, agent_checklist_id, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/{quote(str(agent_checklist_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_conversation_communication_agentchecklist_job(self, agent_checklist_id, communication_id, conversation_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/agentchecklists/{quote(str(agent_checklist_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_conversation_communication_internalmessages(self, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/internalmessages", params=params, **kwargs)

    def post_conversation_communication_internalmessages(self, communication_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/internalmessages", params=params, body=body, **kwargs)

    def get_conversation_communication_internalmessage(self, communication_id, conversation_id, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/internalmessages/{quote(str(message_id), safe='')}", params=params, **kwargs)

    def get_conversation_customattributes(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes", params=params, **kwargs)

    def patch_conversation_customattributes(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes", params=params, body=body, **kwargs)

    def put_conversation_customattributes(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes", params=params, body=body, **kwargs)

    def patch_conversation_customattributes_bulk(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes/bulk", params=params, body=body, **kwargs)

    def put_conversation_customattributes_bulk(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes/bulk", params=params, body=body, **kwargs)

    def delete_conversation_customattribute(self, attributes_id, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes/{quote(str(attributes_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversation_customattribute(self, attributes_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/customattributes/{quote(str(attributes_id), safe='')}", params=params, **kwargs)

    def patch_conversation_participant(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversation_participant_attributes(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/attributes", params=params, body=body, **kwargs)

    def post_conversation_participant_callbacks(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/callbacks", params=params, body=body, **kwargs)

    def delete_conversation_participant_code(self, add_communication_code, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/codes/{quote(str(add_communication_code), safe='')}", params=params, body=body, **kwargs)

    def post_conversation_participant_digits(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/digits", params=params, body=body, **kwargs)

    def delete_conversation_participant_flaggedreason(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/flaggedreason", params=params, body=body, **kwargs)

    def put_conversation_participant_flaggedreason(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/flaggedreason", params=params, body=body, **kwargs)

    def post_conversation_participant_internalmessages_users_communications(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/internalmessages/users/communications", params=params, body=body, **kwargs)

    def post_conversation_participant_replace(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace", params=params, body=body, **kwargs)

    def post_conversation_participant_replace_agent(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace/agent", params=params, body=body, **kwargs)

    def post_conversation_participant_replace_contact_external(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace/contact/external", params=params, body=body, **kwargs)

    def post_conversation_participant_replace_external(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace/external", params=params, body=body, **kwargs)

    def post_conversation_participant_replace_queue(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/replace/queue", params=params, body=body, **kwargs)

    def post_conversation_participant_screenmonitors_sessions(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/screenmonitors/sessions", params=params, body=body, **kwargs)

    def delete_conversation_participant_screenmonitors_session(self, conversation_id, participant_id, screen_monitoring_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/screenmonitors/sessions/{quote(str(screen_monitoring_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversation_participant_screenmonitors_session(self, conversation_id, participant_id, screen_monitoring_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/screenmonitors/sessions/{quote(str(screen_monitoring_id), safe='')}", params=params, **kwargs)

    def get_conversation_participant_secureivrsessions(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/secureivrsessions", params=params, **kwargs)

    def post_conversation_participant_secureivrsessions(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/secureivrsessions", params=params, body=body, **kwargs)

    def get_conversation_participant_secureivrsession(self, conversation_id, participant_id, secure_session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/secureivrsessions/{quote(str(secure_session_id), safe='')}", params=params, **kwargs)

    def post_conversation_participant_transfer(self, conversation_id, participant_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/transfer", params=params, body=body, **kwargs)

    def get_conversation_participant_wrapup(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapup", params=params, **kwargs)

    def get_conversation_participant_wrapupcodes(self, conversation_id, participant_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/participants/{quote(str(participant_id), safe='')}/wrapupcodes", params=params, **kwargs)

    def get_conversation_recordingmetadata(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordingmetadata", params=params, **kwargs)

    def get_conversation_recordingmetadata_recording_id(self, conversation_id, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordingmetadata/{quote(str(recording_id), safe='')}", params=params, **kwargs)

    def get_conversation_recordings(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings", params=params, **kwargs)

    def get_conversation_recording(self, conversation_id, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}", params=params, **kwargs)

    def put_conversation_recording(self, conversation_id, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversation_recording_annotations(self, conversation_id, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}/annotations", params=params, **kwargs)

    def post_conversation_recording_annotations(self, conversation_id, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}/annotations", params=params, body=body, **kwargs)

    def delete_conversation_recording_annotation(self, annotation_id, conversation_id, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, body=body, **kwargs)

    def get_conversation_recording_annotation(self, annotation_id, conversation_id, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, **kwargs)

    def put_conversation_recording_annotation(self, annotation_id, conversation_id, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordings/{quote(str(recording_id), safe='')}/annotations/{quote(str(annotation_id), safe='')}", params=params, body=body, **kwargs)

    def patch_conversation_recordingstate(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/recordingstate", params=params, body=body, **kwargs)

    def get_conversation_secureattributes(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/secureattributes", params=params, **kwargs)

    def patch_conversation_secureattributes(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/secureattributes", params=params, body=body, **kwargs)

    def put_conversation_secureattributes(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/secureattributes", params=params, body=body, **kwargs)

    def get_conversation_suggestions(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/suggestions", params=params, **kwargs)

    def post_conversation_suggestions_feedback(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/suggestions/feedback", params=params, body=body, **kwargs)

    def get_conversation_suggestion(self, conversation_id, suggestion_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/suggestions/{quote(str(suggestion_id), safe='')}", params=params, **kwargs)

    def patch_conversation_suggestion(self, conversation_id, suggestion_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/suggestions/{quote(str(suggestion_id), safe='')}", params=params, body=body, **kwargs)

    def post_conversation_suggestion_engagement(self, conversation_id, suggestion_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/suggestions/{quote(str(suggestion_id), safe='')}/engagement", params=params, body=body, **kwargs)

    def patch_conversation_summary_engagements(self, conversation_id, summary_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/summaries/{quote(str(summary_id), safe='')}/engagements", params=params, body=body, **kwargs)

    def patch_conversation_summary_feedback(self, conversation_id, summary_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/summaries/{quote(str(summary_id), safe='')}/feedback", params=params, body=body, **kwargs)

    def post_conversation_summary_feedback(self, conversation_id, summary_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/summaries/{quote(str(summary_id), safe='')}/feedback", params=params, body=body, **kwargs)

    def put_conversation_tags(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/tags", params=params, body=body, **kwargs)

    def patch_conversation_utilizationlabel(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/conversations/{quote(str(conversation_id), safe='')}/utilizationlabel", params=params, body=body, **kwargs)

    def get_dataextensions_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/dataextensions/coretypes', params=params, **kwargs)

    def get_dataextensions_coretype(self, coretype_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/dataextensions/coretypes/{quote(str(coretype_name), safe='')}", params=params, **kwargs)

    def get_dataextensions_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/dataextensions/limits', params=params, **kwargs)

    def get_dataprivacy_maskingrules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/dataprivacy/maskingrules', params=params, **kwargs)

    def post_dataprivacy_maskingrules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/dataprivacy/maskingrules', params=params, body=body, **kwargs)

    def post_dataprivacy_maskingrules_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/dataprivacy/maskingrules/validate', params=params, body=body, **kwargs)

    def delete_dataprivacy_maskingrule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/dataprivacy/maskingrules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_dataprivacy_maskingrule(self, rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/dataprivacy/maskingrules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def patch_dataprivacy_maskingrule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/dataprivacy/maskingrules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_date(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/date', params=params, **kwargs)

    def get_dependencies_type_entity_type_id_entity_id_connections_requiredby(self, entity_id, entity_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/dependencies/type/{quote(str(entity_type), safe='')}/id/{quote(str(entity_id), safe='')}/connections/requiredby", params=params, **kwargs)

    def get_dependencies_type_entity_type_id_entity_id_connections_requiredbycounts(self, entity_id, entity_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/dependencies/type/{quote(str(entity_type), safe='')}/id/{quote(str(entity_id), safe='')}/connections/requiredbycounts", params=params, **kwargs)

    def get_dependencies_type_entity_type_id_entity_id_connections_requires(self, entity_id, entity_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/dependencies/type/{quote(str(entity_type), safe='')}/id/{quote(str(entity_id), safe='')}/connections/requires", params=params, **kwargs)

    def post_diagnostics_logcapture_browser_entries_download_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/diagnostics/logcapture/browser/entries/download/jobs', params=params, body=body, **kwargs)

    def get_diagnostics_logcapture_browser_entries_download_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/diagnostics/logcapture/browser/entries/download/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_diagnostics_logcapture_browser_entries_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/diagnostics/logcapture/browser/entries/query', params=params, body=body, **kwargs)

    def get_diagnostics_logcapture_browser_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/diagnostics/logcapture/browser/users', params=params, **kwargs)

    def delete_diagnostics_logcapture_browser_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/diagnostics/logcapture/browser/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_diagnostics_logcapture_browser_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/diagnostics/logcapture/browser/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def post_diagnostics_logcapture_browser_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/diagnostics/logcapture/browser/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_documentation_gkn_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/documentation/gkn/search', params=params, **kwargs)

    def post_documentation_gkn_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/documentation/gkn/search', params=params, body=body, **kwargs)

    def get_documentation_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/documentation/search', params=params, **kwargs)

    def post_documentation_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/documentation/search', params=params, body=body, **kwargs)

    def get_download(self, download_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/downloads/{quote(str(download_id), safe='')}", params=params, **kwargs)

    def get_emails_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/emails/settings', params=params, **kwargs)

    def patch_emails_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/emails/settings', params=params, body=body, **kwargs)

    def delete_emails_settings_threading(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/emails/settings/threading', params=params, body=body, **kwargs)

    def get_emails_settings_threading(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/emails/settings/threading', params=params, **kwargs)

    def patch_emails_settings_threading(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/emails/settings/threading', params=params, body=body, **kwargs)

    def get_employeeengagement_celebrations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/employeeengagement/celebrations', params=params, **kwargs)

    def delete_employeeengagement_celebration(self, celebration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/employeeengagement/celebrations/{quote(str(celebration_id), safe='')}", params=params, body=body, **kwargs)

    def patch_employeeengagement_celebration(self, celebration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/employeeengagement/celebrations/{quote(str(celebration_id), safe='')}", params=params, body=body, **kwargs)

    def get_employeeengagement_recognitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/employeeengagement/recognitions', params=params, **kwargs)

    def post_employeeengagement_recognitions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/employeeengagement/recognitions', params=params, body=body, **kwargs)

    def get_employeeengagement_recognition(self, recognition_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/employeeengagement/recognitions/{quote(str(recognition_id), safe='')}", params=params, **kwargs)

    def post_employeeperformance_externalmetrics_data(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/employeeperformance/externalmetrics/data', params=params, body=body, **kwargs)

    def get_employeeperformance_externalmetrics_definitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/employeeperformance/externalmetrics/definitions', params=params, **kwargs)

    def post_employeeperformance_externalmetrics_definitions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/employeeperformance/externalmetrics/definitions', params=params, body=body, **kwargs)

    def delete_employeeperformance_externalmetrics_definition(self, metric_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/employeeperformance/externalmetrics/definitions/{quote(str(metric_id), safe='')}", params=params, body=body, **kwargs)

    def get_employeeperformance_externalmetrics_definition(self, metric_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/employeeperformance/externalmetrics/definitions/{quote(str(metric_id), safe='')}", params=params, **kwargs)

    def patch_employeeperformance_externalmetrics_definition(self, metric_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/employeeperformance/externalmetrics/definitions/{quote(str(metric_id), safe='')}", params=params, body=body, **kwargs)

    def post_events_conversations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/events/conversations', params=params, body=body, **kwargs)

    def post_events_routing_customkpiattributions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/events/routing/customkpiattributions', params=params, body=body, **kwargs)

    def post_events_users_presence(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/events/users/presence', params=params, body=body, **kwargs)

    def post_events_users_routingstatus(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/events/users/routingstatus', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/add', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_divisionviews(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/divisionviews', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_enrich(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/enrich', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/remove', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_unresolved(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/unresolved', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_contacts_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/contacts/update', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_notes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/notes', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_notes_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/notes/add', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_notes_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/notes/remove', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_notes_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/notes/update', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations/add', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations_divisionviews(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations/divisionviews', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations_enrich(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations/enrich', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations/remove', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_organizations_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/organizations/update', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_relationships(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/relationships', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_relationships_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/relationships/add', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_relationships_remove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/relationships/remove', params=params, body=body, **kwargs)

    def post_externalcontacts_bulk_relationships_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/bulk/relationships/update', params=params, body=body, **kwargs)

    def post_externalcontacts_contacts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts', params=params, body=body, **kwargs)

    def post_externalcontacts_contacts_enrich(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts/enrich', params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_exports(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/contacts/exports', params=params, **kwargs)

    def post_externalcontacts_contacts_exports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts/exports', params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_export(self, export_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/exports/{quote(str(export_id), safe='')}", params=params, **kwargs)

    def post_externalcontacts_contacts_merge(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts/merge', params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/contacts/schemas', params=params, **kwargs)

    def post_externalcontacts_contacts_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts/schemas', params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/contacts/schemas/coretypes', params=params, **kwargs)

    def get_externalcontacts_contacts_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_externalcontacts_contacts_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/contacts/schemas/limits', params=params, **kwargs)

    def delete_externalcontacts_contacts_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/contacts/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_contacts_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/contacts/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_contacts_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_externalcontacts_contacts_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def post_externalcontacts_contacts_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/contacts/search', params=params, body=body, **kwargs)

    def delete_externalcontacts_contact(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_contact(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}", params=params, **kwargs)

    def patch_externalcontacts_contact(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}", params=params, body=body, **kwargs)

    def put_externalcontacts_contact(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_contact_identifiers(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/identifiers", params=params, **kwargs)

    def patch_externalcontacts_contact_identifiers(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/identifiers", params=params, body=body, **kwargs)

    def get_externalcontacts_contact_journey_segments(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/journey/segments", params=params, **kwargs)

    def post_externalcontacts_contact_journey_segments(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/journey/segments", params=params, body=body, **kwargs)

    def get_externalcontacts_contact_journey_sessions(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/journey/sessions", params=params, **kwargs)

    def get_externalcontacts_contact_notes(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes", params=params, **kwargs)

    def post_externalcontacts_contact_notes(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes", params=params, body=body, **kwargs)

    def delete_externalcontacts_contact_note(self, contact_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_contact_note(self, contact_id, note_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, **kwargs)

    def patch_externalcontacts_contact_note(self, contact_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def put_externalcontacts_contact_note(self, contact_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def post_externalcontacts_contact_promotion(self, contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/promotion", params=params, body=body, **kwargs)

    def get_externalcontacts_contact_unresolved(self, contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/contacts/{quote(str(contact_id), safe='')}/unresolved", params=params, **kwargs)

    def put_externalcontacts_conversation(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/conversations/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_externalsources(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/externalsources', params=params, **kwargs)

    def post_externalcontacts_externalsources(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/externalsources', params=params, body=body, **kwargs)

    def delete_externalcontacts_externalsource(self, external_source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/externalsources/{quote(str(external_source_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_externalsource(self, external_source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/externalsources/{quote(str(external_source_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_externalsource(self, external_source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/externalsources/{quote(str(external_source_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_graphs_clusterscans(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/graphs/clusterscans', params=params, **kwargs)

    def get_externalcontacts_graphs_clusterscans_latest(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/graphs/clusterscans/latest', params=params, **kwargs)

    def get_externalcontacts_graphs_clusterscans_latest_statistics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/graphs/clusterscans/latest/statistics', params=params, **kwargs)

    def get_externalcontacts_graphs_clusterscan(self, scan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/graphs/clusterscans/{quote(str(scan_id), safe='')}", params=params, **kwargs)

    def get_externalcontacts_graphs_clusterscan_clusters(self, scan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/graphs/clusterscans/{quote(str(scan_id), safe='')}/clusters", params=params, **kwargs)

    def get_externalcontacts_graphs_clusterscan_cluster(self, cluster_id, scan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/graphs/clusterscans/{quote(str(scan_id), safe='')}/clusters/{quote(str(cluster_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_graphs_clusterscan_cluster_merge(self, cluster_id, scan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/graphs/clusterscans/{quote(str(scan_id), safe='')}/clusters/{quote(str(cluster_id), safe='')}/merge", params=params, body=body, **kwargs)

    def get_externalcontacts_graphs_clusterscan_statistics(self, scan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/graphs/clusterscans/{quote(str(scan_id), safe='')}/statistics", params=params, **kwargs)

    def get_externalcontacts_graphs_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/graphs/settings', params=params, **kwargs)

    def put_externalcontacts_graphs_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/externalcontacts/graphs/settings', params=params, body=body, **kwargs)

    def post_externalcontacts_identifierlookup(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/identifierlookup', params=params, body=body, **kwargs)

    def post_externalcontacts_identifierlookup_contacts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/identifierlookup/contacts', params=params, body=body, **kwargs)

    def post_externalcontacts_identifierlookup_organizations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/identifierlookup/organizations', params=params, body=body, **kwargs)

    def post_externalcontacts_import_csv_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/import/csv/jobs', params=params, body=body, **kwargs)

    def get_externalcontacts_import_csv_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/import/csv/settings', params=params, **kwargs)

    def post_externalcontacts_import_csv_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/import/csv/settings', params=params, body=body, **kwargs)

    def delete_externalcontacts_import_csv_setting(self, settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/import/csv/settings/{quote(str(settings_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_import_csv_setting(self, settings_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/import/csv/settings/{quote(str(settings_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_import_csv_setting(self, settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/import/csv/settings/{quote(str(settings_id), safe='')}", params=params, body=body, **kwargs)

    def post_externalcontacts_import_csv_uploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/import/csv/uploads', params=params, body=body, **kwargs)

    def get_externalcontacts_import_csv_upload_details(self, upload_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/import/csv/uploads/{quote(str(upload_id), safe='')}/details", params=params, **kwargs)

    def get_externalcontacts_import_csv_upload_preview(self, upload_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/import/csv/uploads/{quote(str(upload_id), safe='')}/preview", params=params, **kwargs)

    def get_externalcontacts_import_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/import/jobs', params=params, **kwargs)

    def post_externalcontacts_import_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/import/jobs', params=params, body=body, **kwargs)

    def get_externalcontacts_import_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/import/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_import_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/import/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_import_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/import/settings', params=params, **kwargs)

    def post_externalcontacts_import_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/import/settings', params=params, body=body, **kwargs)

    def delete_externalcontacts_import_setting(self, settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/import/settings/{quote(str(settings_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_import_setting(self, settings_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/import/settings/{quote(str(settings_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_import_setting(self, settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/import/settings/{quote(str(settings_id), safe='')}", params=params, body=body, **kwargs)

    def post_externalcontacts_merge_contacts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/merge/contacts', params=params, body=body, **kwargs)

    def get_externalcontacts_notes_exports(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/notes/exports', params=params, **kwargs)

    def post_externalcontacts_notes_exports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/notes/exports', params=params, body=body, **kwargs)

    def get_externalcontacts_notes_export(self, export_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/notes/exports/{quote(str(export_id), safe='')}", params=params, **kwargs)

    def get_externalcontacts_organizations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/organizations', params=params, **kwargs)

    def post_externalcontacts_organizations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/organizations', params=params, body=body, **kwargs)

    def post_externalcontacts_organizations_enrich(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/organizations/enrich', params=params, body=body, **kwargs)

    def get_externalcontacts_organizations_exports(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/organizations/exports', params=params, **kwargs)

    def post_externalcontacts_organizations_exports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/organizations/exports', params=params, body=body, **kwargs)

    def get_externalcontacts_organizations_export(self, export_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/exports/{quote(str(export_id), safe='')}", params=params, **kwargs)

    def get_externalcontacts_organizations_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/organizations/schemas', params=params, **kwargs)

    def post_externalcontacts_organizations_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/organizations/schemas', params=params, body=body, **kwargs)

    def get_externalcontacts_organizations_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/organizations/schemas/coretypes', params=params, **kwargs)

    def get_externalcontacts_organizations_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_externalcontacts_organizations_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/organizations/schemas/limits', params=params, **kwargs)

    def get_externalcontacts_organizations_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_externalcontacts_organizations_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/organizations/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_organizations_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_externalcontacts_organizations_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def delete_externalcontacts_organization(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_organization(self, external_organization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}", params=params, **kwargs)

    def patch_externalcontacts_organization(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}", params=params, body=body, **kwargs)

    def put_externalcontacts_organization(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_organization_contacts(self, external_organization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/contacts", params=params, **kwargs)

    def get_externalcontacts_organization_identifiers(self, external_organization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/identifiers", params=params, **kwargs)

    def patch_externalcontacts_organization_identifiers(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/identifiers", params=params, body=body, **kwargs)

    def get_externalcontacts_organization_notes(self, external_organization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes", params=params, **kwargs)

    def post_externalcontacts_organization_notes(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes", params=params, body=body, **kwargs)

    def delete_externalcontacts_organization_note(self, external_organization_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_organization_note(self, external_organization_id, note_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, **kwargs)

    def patch_externalcontacts_organization_note(self, external_organization_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def put_externalcontacts_organization_note(self, external_organization_id, note_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/notes/{quote(str(note_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_organization_relationships(self, external_organization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/relationships", params=params, **kwargs)

    def delete_externalcontacts_organization_trustor(self, external_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/trustor", params=params, body=body, **kwargs)

    def put_externalcontacts_organization_trustor_trustor_id(self, external_organization_id, trustor_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/organizations/{quote(str(external_organization_id), safe='')}/trustor/{quote(str(trustor_id), safe='')}", params=params, body=body, **kwargs)

    def post_externalcontacts_relationships(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/relationships', params=params, body=body, **kwargs)

    def get_externalcontacts_relationships_exports(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/relationships/exports', params=params, **kwargs)

    def post_externalcontacts_relationships_exports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/externalcontacts/relationships/exports', params=params, body=body, **kwargs)

    def get_externalcontacts_relationships_export(self, export_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/relationships/exports/{quote(str(export_id), safe='')}", params=params, **kwargs)

    def delete_externalcontacts_relationship(self, relationship_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/externalcontacts/relationships/{quote(str(relationship_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_relationship(self, relationship_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/externalcontacts/relationships/{quote(str(relationship_id), safe='')}", params=params, **kwargs)

    def patch_externalcontacts_relationship(self, relationship_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/externalcontacts/relationships/{quote(str(relationship_id), safe='')}", params=params, body=body, **kwargs)

    def put_externalcontacts_relationship(self, relationship_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/externalcontacts/relationships/{quote(str(relationship_id), safe='')}", params=params, body=body, **kwargs)

    def get_externalcontacts_reversewhitepageslookup(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/reversewhitepageslookup', params=params, **kwargs)

    def get_externalcontacts_scan_contacts_divisionviews_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/contacts/divisionviews/all', params=params, **kwargs)

    def get_externalcontacts_scan_notes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/notes', params=params, **kwargs)

    def get_externalcontacts_scan_notes_divisionviews_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/notes/divisionviews/all', params=params, **kwargs)

    def get_externalcontacts_scan_organizations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/organizations', params=params, **kwargs)

    def get_externalcontacts_scan_organizations_divisionviews_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/organizations/divisionviews/all', params=params, **kwargs)

    def get_externalcontacts_scan_relationships(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/relationships', params=params, **kwargs)

    def get_externalcontacts_scan_relationships_divisionviews_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/scan/relationships/divisionviews/all', params=params, **kwargs)

    def delete_externalcontacts_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/externalcontacts/settings', params=params, body=body, **kwargs)

    def get_externalcontacts_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/externalcontacts/settings', params=params, **kwargs)

    def put_externalcontacts_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/externalcontacts/settings', params=params, body=body, **kwargs)

    def get_fax_documents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/fax/documents', params=params, **kwargs)

    def delete_fax_document(self, document_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/fax/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def get_fax_document(self, document_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/fax/documents/{quote(str(document_id), safe='')}", params=params, **kwargs)

    def put_fax_document(self, document_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/fax/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def get_fax_document_content(self, document_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/fax/documents/{quote(str(document_id), safe='')}/content", params=params, **kwargs)

    def get_fax_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/fax/settings', params=params, **kwargs)

    def put_fax_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/fax/settings', params=params, body=body, **kwargs)

    def get_fax_summary(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/fax/summary', params=params, **kwargs)

    def get_fax_fax_id_status(self, fax_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/fax/{quote(str(fax_id), safe='')}/status", params=params, **kwargs)

    def get_fieldconfig(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/fieldconfig', params=params, **kwargs)

    def delete_flows(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/flows', params=params, body=body, **kwargs)

    def post_flows(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows', params=params, body=body, **kwargs)

    def post_flows_actions_deactivate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/actions/deactivate', params=params, body=body, **kwargs)

    def post_flows_actions_revert(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/actions/revert', params=params, body=body, **kwargs)

    def post_flows_actions_unlock(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/actions/unlock', params=params, body=body, **kwargs)

    def post_flows_datatables(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/datatables', params=params, body=body, **kwargs)

    def get_flows_datatables_divisionview(self, datatable_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/datatables/divisionviews/{quote(str(datatable_id), safe='')}", params=params, **kwargs)

    def delete_flows_datatable(self, datatable_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}", params=params, body=body, **kwargs)

    def get_flows_datatable(self, datatable_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}", params=params, **kwargs)

    def put_flows_datatable(self, datatable_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}", params=params, body=body, **kwargs)

    def post_flows_datatable_export_jobs(self, datatable_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/export/jobs", params=params, body=body, **kwargs)

    def get_flows_datatable_export_job(self, datatable_id, export_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/export/jobs/{quote(str(export_job_id), safe='')}", params=params, **kwargs)

    def post_flows_datatable_import_csv_jobs(self, datatable_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/import/csv/jobs", params=params, body=body, **kwargs)

    def get_flows_datatable_import_jobs(self, datatable_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/import/jobs", params=params, **kwargs)

    def post_flows_datatable_import_jobs(self, datatable_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/import/jobs", params=params, body=body, **kwargs)

    def get_flows_datatable_import_job(self, datatable_id, import_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/datatables/{quote(str(datatable_id), safe='')}/import/jobs/{quote(str(import_job_id), safe='')}", params=params, **kwargs)

    def get_flows_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/divisionviews', params=params, **kwargs)

    def post_flows_export_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/export/jobs', params=params, body=body, **kwargs)

    def get_flows_export_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/export/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_flows_instances_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/instances/jobs', params=params, body=body, **kwargs)

    def get_flows_instances_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/instances/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_flows_instances_querycapabilities(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/instances/querycapabilities', params=params, **kwargs)

    def get_flows_instances_settings_executiondata(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/instances/settings/executiondata', params=params, **kwargs)

    def patch_flows_instances_settings_executiondata(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/flows/instances/settings/executiondata', params=params, body=body, **kwargs)

    def get_flows_instances_settings_loglevels(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/instances/settings/loglevels', params=params, **kwargs)

    def get_flows_instances_settings_loglevels_characteristics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/instances/settings/loglevels/characteristics', params=params, **kwargs)

    def delete_flows_instances_settings_loglevels_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/flows/instances/settings/loglevels/default', params=params, body=body, **kwargs)

    def get_flows_instances_settings_loglevels_default(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/instances/settings/loglevels/default', params=params, **kwargs)

    def put_flows_instances_settings_loglevels_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/flows/instances/settings/loglevels/default', params=params, body=body, **kwargs)

    def get_flows_instance(self, instance_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/instances/{quote(str(instance_id), safe='')}", params=params, **kwargs)

    def post_flows_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/jobs', params=params, body=body, **kwargs)

    def get_flows_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_flows_lookup(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/lookup', params=params, **kwargs)

    def post_flows_milestones(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/milestones', params=params, body=body, **kwargs)

    def get_flows_milestones_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/milestones/divisionviews', params=params, **kwargs)

    def delete_flows_milestone(self, milestone_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/flows/milestones/{quote(str(milestone_id), safe='')}", params=params, body=body, **kwargs)

    def get_flows_milestone(self, milestone_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/milestones/{quote(str(milestone_id), safe='')}", params=params, **kwargs)

    def put_flows_milestone(self, milestone_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/flows/milestones/{quote(str(milestone_id), safe='')}", params=params, body=body, **kwargs)

    def post_flows_outcomes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/flows/outcomes', params=params, body=body, **kwargs)

    def get_flows_outcomes_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/flows/outcomes/divisionviews', params=params, **kwargs)

    def get_flows_outcome(self, flow_outcome_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/outcomes/{quote(str(flow_outcome_id), safe='')}", params=params, **kwargs)

    def put_flows_outcome(self, flow_outcome_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/flows/outcomes/{quote(str(flow_outcome_id), safe='')}", params=params, body=body, **kwargs)

    def delete_flow(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/flows/{quote(str(flow_id), safe='')}", params=params, body=body, **kwargs)

    def put_flow(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/flows/{quote(str(flow_id), safe='')}", params=params, body=body, **kwargs)

    def post_flow_history(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/{quote(str(flow_id), safe='')}/history", params=params, body=body, **kwargs)

    def get_flow_history_history_id(self, flow_id, history_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/history/{quote(str(history_id), safe='')}", params=params, **kwargs)

    def delete_flow_instances_settings_loglevels(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/flows/{quote(str(flow_id), safe='')}/instances/settings/loglevels", params=params, body=body, **kwargs)

    def get_flow_instances_settings_loglevels(self, flow_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/instances/settings/loglevels", params=params, **kwargs)

    def post_flow_instances_settings_loglevels(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/{quote(str(flow_id), safe='')}/instances/settings/loglevels", params=params, body=body, **kwargs)

    def put_flow_instances_settings_loglevels(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/flows/{quote(str(flow_id), safe='')}/instances/settings/loglevels", params=params, body=body, **kwargs)

    def get_flow_versions(self, flow_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions", params=params, **kwargs)

    def post_flow_versions(self, flow_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions", params=params, body=body, **kwargs)

    def get_flow_version(self, flow_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def get_flow_version_configuration(self, flow_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions/{quote(str(version_id), safe='')}/configuration", params=params, **kwargs)

    def get_flow_version_health(self, flow_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions/{quote(str(version_id), safe='')}/health", params=params, **kwargs)

    def get_flow_version_intent_health(self, flow_id, intent_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions/{quote(str(version_id), safe='')}/intents/{quote(str(intent_id), safe='')}/health", params=params, **kwargs)

    def get_flow_version_intent_utterance_health(self, flow_id, intent_id, utterance_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/flows/{quote(str(flow_id), safe='')}/versions/{quote(str(version_id), safe='')}/intents/{quote(str(intent_id), safe='')}/utterances/{quote(str(utterance_id), safe='')}/health", params=params, **kwargs)

    def get_gamification_contests(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/contests', params=params, **kwargs)

    def post_gamification_contests(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/gamification/contests', params=params, body=body, **kwargs)

    def get_gamification_contests_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/contests/me', params=params, **kwargs)

    def post_gamification_contests_uploads_prizeimages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/gamification/contests/uploads/prizeimages', params=params, body=body, **kwargs)

    def delete_gamification_contest(self, contest_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}", params=params, body=body, **kwargs)

    def get_gamification_contest(self, contest_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}", params=params, **kwargs)

    def patch_gamification_contest(self, contest_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}", params=params, body=body, **kwargs)

    def put_gamification_contest(self, contest_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}", params=params, body=body, **kwargs)

    def get_gamification_contest_agents_scores(self, contest_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}/agents/scores", params=params, **kwargs)

    def get_gamification_contest_agents_scores_me(self, contest_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}/agents/scores/me", params=params, **kwargs)

    def get_gamification_contest_agents_scores_trends(self, contest_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}/agents/scores/trends", params=params, **kwargs)

    def get_gamification_contest_agents_scores_trends_me(self, contest_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}/agents/scores/trends/me", params=params, **kwargs)

    def get_gamification_contest_prizeimage(self, contest_id, prize_image_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/contests/{quote(str(contest_id), safe='')}/prizeimages/{quote(str(prize_image_id), safe='')}", params=params, **kwargs)

    def get_gamification_insights(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights', params=params, **kwargs)

    def get_gamification_insights_details(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/details', params=params, **kwargs)

    def get_gamification_insights_groups_trends(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/groups/trends', params=params, **kwargs)

    def get_gamification_insights_groups_trends_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/groups/trends/all', params=params, **kwargs)

    def get_gamification_insights_managers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/managers', params=params, **kwargs)

    def get_gamification_insights_members(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/members', params=params, **kwargs)

    def get_gamification_insights_rankings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/rankings', params=params, **kwargs)

    def get_gamification_insights_trends(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/insights/trends', params=params, **kwargs)

    def get_gamification_insights_user_details(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/insights/users/{quote(str(user_id), safe='')}/details", params=params, **kwargs)

    def get_gamification_insights_user_trends(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/insights/users/{quote(str(user_id), safe='')}/trends", params=params, **kwargs)

    def get_gamification_leaderboard(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/leaderboard', params=params, **kwargs)

    def get_gamification_leaderboard_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/leaderboard/all', params=params, **kwargs)

    def get_gamification_leaderboard_all_bestpoints(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/leaderboard/all/bestpoints', params=params, **kwargs)

    def get_gamification_leaderboard_bestpoints(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/leaderboard/bestpoints', params=params, **kwargs)

    def get_gamification_metricdefinitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/metricdefinitions', params=params, **kwargs)

    def get_gamification_metricdefinition(self, metric_definition_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/metricdefinitions/{quote(str(metric_definition_id), safe='')}", params=params, **kwargs)

    def get_gamification_profiles(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/profiles', params=params, **kwargs)

    def post_gamification_profiles(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/gamification/profiles', params=params, body=body, **kwargs)

    def get_gamification_profiles_users_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/profiles/users/me', params=params, **kwargs)

    def post_gamification_profiles_users_me_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/gamification/profiles/users/me/query', params=params, body=body, **kwargs)

    def post_gamification_profiles_user_query(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/users/{quote(str(user_id), safe='')}/query", params=params, body=body, **kwargs)

    def get_gamification_profile(self, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}", params=params, **kwargs)

    def put_gamification_profile(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}", params=params, body=body, **kwargs)

    def post_gamification_profile_activate(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/activate", params=params, body=body, **kwargs)

    def post_gamification_profile_deactivate(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/deactivate", params=params, body=body, **kwargs)

    def get_gamification_profile_members(self, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/members", params=params, **kwargs)

    def post_gamification_profile_members(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/members", params=params, body=body, **kwargs)

    def post_gamification_profile_members_validate(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/members/validate", params=params, body=body, **kwargs)

    def get_gamification_profile_metrics(self, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/metrics", params=params, **kwargs)

    def post_gamification_profile_metrics(self, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/metrics", params=params, body=body, **kwargs)

    def get_gamification_profile_metrics_objectivedetails(self, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/metrics/objectivedetails", params=params, **kwargs)

    def put_gamification_profile_metric(self, metric_id, profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/gamification/profiles/{quote(str(profile_id), safe='')}/metrics/{quote(str(metric_id), safe='')}", params=params, body=body, **kwargs)

    def post_gamification_profile_metric_link(self, source_metric_id, source_profile_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/gamification/profiles/{quote(str(source_profile_id), safe='')}/metrics/{quote(str(source_metric_id), safe='')}/link", params=params, body=body, **kwargs)

    def get_gamification_scorecards(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards', params=params, **kwargs)

    def get_gamification_scorecards_attendance(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/attendance', params=params, **kwargs)

    def get_gamification_scorecards_bestpoints(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/bestpoints', params=params, **kwargs)

    def get_gamification_scorecards_points_alltime(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/points/alltime', params=params, **kwargs)

    def get_gamification_scorecards_points_average(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/points/average', params=params, **kwargs)

    def get_gamification_scorecards_points_trends(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/points/trends', params=params, **kwargs)

    def get_gamification_scorecards_profile_metric_users_values_trends(self, metric_id, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/profiles/{quote(str(profile_id), safe='')}/metrics/{quote(str(metric_id), safe='')}/users/values/trends", params=params, **kwargs)

    def get_gamification_scorecards_profile_metric_user_values_trends(self, metric_id, profile_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/profiles/{quote(str(profile_id), safe='')}/metrics/{quote(str(metric_id), safe='')}/users/{quote(str(user_id), safe='')}/values/trends", params=params, **kwargs)

    def get_gamification_scorecards_profile_metric_values_trends(self, metric_id, profile_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/profiles/{quote(str(profile_id), safe='')}/metrics/{quote(str(metric_id), safe='')}/values/trends", params=params, **kwargs)

    def get_gamification_scorecards_users_points_average(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/users/points/average', params=params, **kwargs)

    def get_gamification_scorecards_users_values_average(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/users/values/average', params=params, **kwargs)

    def get_gamification_scorecards_users_values_trends(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/users/values/trends', params=params, **kwargs)

    def get_gamification_scorecards_user_attendance(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/users/{quote(str(user_id), safe='')}/attendance", params=params, **kwargs)

    def get_gamification_scorecards_user_bestpoints(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/users/{quote(str(user_id), safe='')}/bestpoints", params=params, **kwargs)

    def get_gamification_scorecards_user_points_alltime(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/users/{quote(str(user_id), safe='')}/points/alltime", params=params, **kwargs)

    def get_gamification_scorecards_user_points_trends(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/users/{quote(str(user_id), safe='')}/points/trends", params=params, **kwargs)

    def get_gamification_scorecards_user_values_trends(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/scorecards/users/{quote(str(user_id), safe='')}/values/trends", params=params, **kwargs)

    def get_gamification_scorecards_values_average(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/values/average', params=params, **kwargs)

    def get_gamification_scorecards_values_trends(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/scorecards/values/trends', params=params, **kwargs)

    def get_gamification_status(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/status', params=params, **kwargs)

    def put_gamification_status(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/gamification/status', params=params, body=body, **kwargs)

    def get_gamification_templates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gamification/templates', params=params, **kwargs)

    def get_gamification_template(self, template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/gamification/templates/{quote(str(template_id), safe='')}", params=params, **kwargs)

    def get_gdpr_requests(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/gdpr/requests', params=params, **kwargs)

    def get_geolocations_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/geolocations/settings', params=params, **kwargs)

    def patch_geolocations_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/geolocations/settings', params=params, body=body, **kwargs)

    def get_greetings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/greetings', params=params, **kwargs)

    def post_greetings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/greetings', params=params, body=body, **kwargs)

    def get_greetings_defaults(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/greetings/defaults', params=params, **kwargs)

    def put_greetings_defaults(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/greetings/defaults', params=params, body=body, **kwargs)

    def delete_greeting(self, greeting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}", params=params, body=body, **kwargs)

    def get_greeting(self, greeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}", params=params, **kwargs)

    def put_greeting(self, greeting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}", params=params, body=body, **kwargs)

    def get_greeting_downloads(self, greeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}/downloads", params=params, **kwargs)

    def get_greeting_groups_downloads(self, greeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}/groups/downloads", params=params, **kwargs)

    def get_greeting_media(self, greeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}/media", params=params, **kwargs)

    def get_greeting_users_downloads(self, greeting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/greetings/{quote(str(greeting_id), safe='')}/users/downloads", params=params, **kwargs)

    def post_groups(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/groups', params=params, body=body, **kwargs)

    def get_groups_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/groups/search', params=params, **kwargs)

    def post_groups_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/groups/search', params=params, body=body, **kwargs)

    def delete_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def get_group(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}", params=params, **kwargs)

    def put_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def get_group_greetings(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}/greetings", params=params, **kwargs)

    def post_group_greetings(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/groups/{quote(str(group_id), safe='')}/greetings", params=params, body=body, **kwargs)

    def get_group_greetings_defaults(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}/greetings/defaults", params=params, **kwargs)

    def put_group_greetings_defaults(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/groups/{quote(str(group_id), safe='')}/greetings/defaults", params=params, body=body, **kwargs)

    def get_group_individuals(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}/individuals", params=params, **kwargs)

    def delete_group_members(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/groups/{quote(str(group_id), safe='')}/members", params=params, body=body, **kwargs)

    def get_group_members(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}/members", params=params, **kwargs)

    def get_group_profile(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/groups/{quote(str(group_id), safe='')}/profile", params=params, **kwargs)

    def get_guides(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/guides', params=params, **kwargs)

    def post_guides(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/guides', params=params, body=body, **kwargs)

    def post_guides_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/guides/jobs', params=params, body=body, **kwargs)

    def get_guides_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/guides/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_guides_uploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/guides/uploads', params=params, body=body, **kwargs)

    def get_guide(self, guide_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/guides/{quote(str(guide_id), safe='')}", params=params, **kwargs)

    def patch_guide(self, guide_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/guides/{quote(str(guide_id), safe='')}", params=params, body=body, **kwargs)

    def delete_guide_jobs(self, guide_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/guides/{quote(str(guide_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_guide_job(self, guide_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/guides/{quote(str(guide_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_guide_session_turns(self, guide_id, guide_session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/guides/{quote(str(guide_id), safe='')}/sessions/{quote(str(guide_session_id), safe='')}/turns", params=params, body=body, **kwargs)

    def post_guide_versions(self, guide_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/guides/{quote(str(guide_id), safe='')}/versions", params=params, body=body, **kwargs)

    def get_guide_version(self, guide_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/guides/{quote(str(guide_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def patch_guide_version(self, guide_id, version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/guides/{quote(str(guide_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, body=body, **kwargs)

    def post_guide_version_jobs(self, guide_id, version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/guides/{quote(str(guide_id), safe='')}/versions/{quote(str(version_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_guide_version_job(self, guide_id, job_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/guides/{quote(str(guide_id), safe='')}/versions/{quote(str(version_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_identityproviders(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders', params=params, **kwargs)

    def post_identityproviders(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/identityproviders', params=params, body=body, **kwargs)

    def delete_identityproviders_adfs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/adfs', params=params, body=body, **kwargs)

    def get_identityproviders_adfs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/adfs', params=params, **kwargs)

    def put_identityproviders_adfs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/adfs', params=params, body=body, **kwargs)

    def delete_identityproviders_cic(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/cic', params=params, body=body, **kwargs)

    def get_identityproviders_cic(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/cic', params=params, **kwargs)

    def put_identityproviders_cic(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/cic', params=params, body=body, **kwargs)

    def delete_identityproviders_generic(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/generic', params=params, body=body, **kwargs)

    def get_identityproviders_generic(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/generic', params=params, **kwargs)

    def put_identityproviders_generic(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/generic', params=params, body=body, **kwargs)

    def delete_identityproviders_gsuite(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/gsuite', params=params, body=body, **kwargs)

    def get_identityproviders_gsuite(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/gsuite', params=params, **kwargs)

    def put_identityproviders_gsuite(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/gsuite', params=params, body=body, **kwargs)

    def delete_identityproviders_identitynow(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/identitynow', params=params, body=body, **kwargs)

    def get_identityproviders_identitynow(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/identitynow', params=params, **kwargs)

    def put_identityproviders_identitynow(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/identitynow', params=params, body=body, **kwargs)

    def delete_identityproviders_okta(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/okta', params=params, body=body, **kwargs)

    def get_identityproviders_okta(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/okta', params=params, **kwargs)

    def put_identityproviders_okta(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/okta', params=params, body=body, **kwargs)

    def delete_identityproviders_onelogin(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/onelogin', params=params, body=body, **kwargs)

    def get_identityproviders_onelogin(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/onelogin', params=params, **kwargs)

    def put_identityproviders_onelogin(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/onelogin', params=params, body=body, **kwargs)

    def delete_identityproviders_ping(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/ping', params=params, body=body, **kwargs)

    def get_identityproviders_ping(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/ping', params=params, **kwargs)

    def put_identityproviders_ping(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/ping', params=params, body=body, **kwargs)

    def delete_identityproviders_purecloud(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/purecloud', params=params, body=body, **kwargs)

    def get_identityproviders_purecloud(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/purecloud', params=params, **kwargs)

    def put_identityproviders_purecloud(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/purecloud', params=params, body=body, **kwargs)

    def delete_identityproviders_pureengage(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/pureengage', params=params, body=body, **kwargs)

    def get_identityproviders_pureengage(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/pureengage', params=params, **kwargs)

    def put_identityproviders_pureengage(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/pureengage', params=params, body=body, **kwargs)

    def delete_identityproviders_salesforce(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/identityproviders/salesforce', params=params, body=body, **kwargs)

    def get_identityproviders_salesforce(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/identityproviders/salesforce', params=params, **kwargs)

    def put_identityproviders_salesforce(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/identityproviders/salesforce', params=params, body=body, **kwargs)

    def delete_identityprovider(self, provider_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/identityproviders/{quote(str(provider_id), safe='')}", params=params, body=body, **kwargs)

    def get_identityprovider(self, provider_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/identityproviders/{quote(str(provider_id), safe='')}", params=params, **kwargs)

    def put_identityprovider(self, provider_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/identityproviders/{quote(str(provider_id), safe='')}", params=params, body=body, **kwargs)

    def get_infrastructureascode_accelerators(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/infrastructureascode/accelerators', params=params, **kwargs)

    def get_infrastructureascode_accelerator(self, accelerator_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/infrastructureascode/accelerators/{quote(str(accelerator_id), safe='')}", params=params, **kwargs)

    def get_infrastructureascode_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/infrastructureascode/jobs', params=params, **kwargs)

    def post_infrastructureascode_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/infrastructureascode/jobs', params=params, body=body, **kwargs)

    def get_infrastructureascode_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/infrastructureascode/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_integrations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/integrations', params=params, body=body, **kwargs)

    def post_integrations_actions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/integrations/actions', params=params, body=body, **kwargs)

    def get_integrations_actions_categories(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/actions/categories', params=params, **kwargs)

    def get_integrations_actions_certificates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/actions/certificates', params=params, **kwargs)

    def get_integrations_actions_certificates_truststore(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/actions/certificates/truststore', params=params, **kwargs)

    def get_integrations_actions_drafts(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/actions/drafts', params=params, **kwargs)

    def post_integrations_actions_drafts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/integrations/actions/drafts', params=params, body=body, **kwargs)

    def get_integrations_actions_functions_runtimes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/actions/functions/runtimes', params=params, **kwargs)

    def delete_integrations_action(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}", params=params, body=body, **kwargs)

    def patch_integrations_action(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}", params=params, body=body, **kwargs)

    def delete_integrations_action_draft(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft", params=params, body=body, **kwargs)

    def patch_integrations_action_draft(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft", params=params, body=body, **kwargs)

    def post_integrations_action_draft(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft", params=params, body=body, **kwargs)

    def get_integrations_action_draft_function(self, action_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/function", params=params, **kwargs)

    def put_integrations_action_draft_function(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/function", params=params, body=body, **kwargs)

    def post_integrations_action_draft_function_upload(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/function/upload", params=params, body=body, **kwargs)

    def post_integrations_action_draft_publish(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/publish", params=params, body=body, **kwargs)

    def get_integrations_action_draft_schema(self, action_id, file_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/schemas/{quote(str(file_name), safe='')}", params=params, **kwargs)

    def get_integrations_action_draft_template(self, action_id, file_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/templates/{quote(str(file_name), safe='')}", params=params, **kwargs)

    def post_integrations_action_draft_test(self, action_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/test", params=params, body=body, **kwargs)

    def get_integrations_action_draft_validation(self, action_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/draft/validation", params=params, **kwargs)

    def get_integrations_action_function(self, action_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/function", params=params, **kwargs)

    def get_integrations_action_schema(self, action_id, file_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/schemas/{quote(str(file_name), safe='')}", params=params, **kwargs)

    def get_integrations_action_template(self, action_id, file_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/actions/{quote(str(action_id), safe='')}/templates/{quote(str(file_name), safe='')}", params=params, **kwargs)

    def get_integrations_botconnector_integration_id_bots(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/botconnector/{quote(str(integration_id), safe='')}/bots", params=params, **kwargs)

    def put_integrations_botconnector_integration_id_bots(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/botconnector/{quote(str(integration_id), safe='')}/bots", params=params, body=body, **kwargs)

    def get_integrations_botconnector_integration_id_bots_summaries(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/botconnector/{quote(str(integration_id), safe='')}/bots/summaries", params=params, **kwargs)

    def get_integrations_botconnector_integration_id_bot(self, bot_id, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/botconnector/{quote(str(integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}", params=params, **kwargs)

    def get_integrations_botconnector_integration_id_bot_versions(self, bot_id, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/botconnector/{quote(str(integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}/versions", params=params, **kwargs)

    def get_integrations_clientapps(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/clientapps', params=params, **kwargs)

    def get_integrations_credentials(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/credentials', params=params, **kwargs)

    def post_integrations_credentials(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/integrations/credentials', params=params, body=body, **kwargs)

    def get_integrations_credentials_listing(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/credentials/listing', params=params, **kwargs)

    def get_integrations_credentials_types(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/credentials/types', params=params, **kwargs)

    def delete_integrations_credential(self, credential_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/integrations/credentials/{quote(str(credential_id), safe='')}", params=params, body=body, **kwargs)

    def get_integrations_credential(self, credential_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/credentials/{quote(str(credential_id), safe='')}", params=params, **kwargs)

    def put_integrations_credential(self, credential_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/credentials/{quote(str(credential_id), safe='')}", params=params, body=body, **kwargs)

    def get_integrations_speech_audioconnector(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/audioconnector', params=params, **kwargs)

    def get_integrations_speech_audioconnector_integration_id(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/audioconnector/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_dialogflow_agents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/dialogflow/agents', params=params, **kwargs)

    def get_integrations_speech_dialogflow_agent(self, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/dialogflow/agents/{quote(str(agent_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_dialogflowcx_agents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/dialogflowcx/agents', params=params, **kwargs)

    def get_integrations_speech_dialogflowcx_agent(self, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/dialogflowcx/agents/{quote(str(agent_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_lex_bot_alias(self, alias_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/lex/bot/alias/{quote(str(alias_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_lex_bot_bot_id_aliases(self, bot_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/lex/bot/{quote(str(bot_id), safe='')}/aliases", params=params, **kwargs)

    def get_integrations_speech_lex_bots(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/lex/bots', params=params, **kwargs)

    def get_integrations_speech_lexv2_bot_alias(self, alias_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/lexv2/bot/alias/{quote(str(alias_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_lexv2_bot_bot_id_aliases(self, bot_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/lexv2/bot/{quote(str(bot_id), safe='')}/aliases", params=params, **kwargs)

    def get_integrations_speech_lexv2_bots(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/lexv2/bots', params=params, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bots(self, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots", params=params, **kwargs)

    def post_integrations_speech_nuance_nuance_integration_id_bots_jobs(self, nuance_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/jobs", params=params, body=body, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bots_job(self, job_id, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bots_job_results(self, job_id, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def put_integrations_speech_nuance_nuance_integration_id_bots_launch_settings(self, nuance_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/launch/settings", params=params, body=body, **kwargs)

    def post_integrations_speech_nuance_nuance_integration_id_bots_launch_validate(self, nuance_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/launch/validate", params=params, body=body, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bot(self, bot_id, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}", params=params, **kwargs)

    def post_integrations_speech_nuance_nuance_integration_id_bot_jobs(self, bot_id, nuance_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bot_job(self, bot_id, job_id, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_nuance_nuance_integration_id_bot_job_results(self, bot_id, job_id, nuance_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/nuance/{quote(str(nuance_integration_id), safe='')}/bots/{quote(str(bot_id), safe='')}/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def get_integrations_speech_stt_engines(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/stt/engines', params=params, **kwargs)

    def get_integrations_speech_stt_engine(self, engine_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/stt/engines/{quote(str(engine_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_tts_engines(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/tts/engines', params=params, **kwargs)

    def get_integrations_speech_tts_engine(self, engine_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/tts/engines/{quote(str(engine_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_tts_engine_voices(self, engine_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/tts/engines/{quote(str(engine_id), safe='')}/voices", params=params, **kwargs)

    def get_integrations_speech_tts_engine_voice(self, engine_id, voice_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/speech/tts/engines/{quote(str(engine_id), safe='')}/voices/{quote(str(voice_id), safe='')}", params=params, **kwargs)

    def get_integrations_speech_tts_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/speech/tts/settings', params=params, **kwargs)

    def put_integrations_speech_tts_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/integrations/speech/tts/settings', params=params, body=body, **kwargs)

    def get_integrations_types(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/types', params=params, **kwargs)

    def get_integrations_type(self, type_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/types/{quote(str(type_id), safe='')}", params=params, **kwargs)

    def get_integrations_type_configschema(self, config_type, type_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/types/{quote(str(type_id), safe='')}/configschemas/{quote(str(config_type), safe='')}", params=params, **kwargs)

    def get_integrations_unifiedcommunications_clientapps(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/unifiedcommunications/clientapps', params=params, **kwargs)

    def get_integrations_unifiedcommunications_clientapp(self, uc_integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/unifiedcommunications/clientapps/{quote(str(uc_integration_id), safe='')}", params=params, **kwargs)

    def put_integrations_unifiedcommunication_thirdpartypresences(self, uc_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/unifiedcommunications/{quote(str(uc_integration_id), safe='')}/thirdpartypresences", params=params, body=body, **kwargs)

    def get_integrations_userapps(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/integrations/userapps', params=params, **kwargs)

    def post_integrations_webhook_events(self, token_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/integrations/webhooks/{quote(str(token_id), safe='')}/events", params=params, body=body, **kwargs)

    def delete_integration(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/integrations/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_integration(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/{quote(str(integration_id), safe='')}", params=params, **kwargs)

    def patch_integration(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/integrations/{quote(str(integration_id), safe='')}", params=params, body=body, **kwargs)

    def get_integration_config_current(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/integrations/{quote(str(integration_id), safe='')}/config/current", params=params, **kwargs)

    def put_integration_config_current(self, integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/integrations/{quote(str(integration_id), safe='')}/config/current", params=params, body=body, **kwargs)

    def get_intents_assignments_externalcontact(self, external_contact_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/intents/assignments/externalcontacts/{quote(str(external_contact_id), safe='')}", params=params, **kwargs)

    def post_intents_assignments_externalcontact_customerintent_assignment(self, customer_intent_id, external_contact_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/intents/assignments/externalcontacts/{quote(str(external_contact_id), safe='')}/customerintents/{quote(str(customer_intent_id), safe='')}/assignment", params=params, body=body, **kwargs)

    def get_intents_categories(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/intents/categories', params=params, **kwargs)

    def post_intents_categories(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/intents/categories', params=params, body=body, **kwargs)

    def delete_intents_category(self, category_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/intents/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def get_intents_category(self, category_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/intents/categories/{quote(str(category_id), safe='')}", params=params, **kwargs)

    def patch_intents_category(self, category_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/intents/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def get_intents_customerintents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/intents/customerintents', params=params, **kwargs)

    def post_intents_customerintents(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/intents/customerintents', params=params, body=body, **kwargs)

    def post_intents_customerintents_bulk_retrieve(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/intents/customerintents/bulk/retrieve', params=params, body=body, **kwargs)

    def delete_intents_customerintent(self, customer_intent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}", params=params, body=body, **kwargs)

    def get_intents_customerintent(self, customer_intent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}", params=params, **kwargs)

    def patch_intents_customerintent(self, customer_intent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}", params=params, body=body, **kwargs)

    def get_intents_customerintent_sourceintents(self, customer_intent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}/sourceintents", params=params, **kwargs)

    def post_intents_customerintent_sourceintents_bulk_add(self, customer_intent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}/sourceintents/bulk/add", params=params, body=body, **kwargs)

    def post_intents_customerintent_sourceintents_bulk_remove(self, customer_intent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/intents/customerintents/{quote(str(customer_intent_id), safe='')}/sourceintents/bulk/remove", params=params, body=body, **kwargs)

    def get_intents_sourceintents(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/intents/sourceintents', params=params, **kwargs)

    def get_ipranges(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/ipranges', params=params, **kwargs)

    def get_journey_actionmaps(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/actionmaps', params=params, **kwargs)

    def post_journey_actionmaps(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/actionmaps', params=params, body=body, **kwargs)

    def post_journey_actionmaps_estimates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/actionmaps/estimates/jobs', params=params, body=body, **kwargs)

    def get_journey_actionmaps_estimates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/actionmaps/estimates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_journey_actionmaps_estimates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/actionmaps/estimates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def delete_journey_actionmap(self, action_map_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/actionmaps/{quote(str(action_map_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_actionmap(self, action_map_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/actionmaps/{quote(str(action_map_id), safe='')}", params=params, **kwargs)

    def patch_journey_actionmap(self, action_map_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/actionmaps/{quote(str(action_map_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_actiontargets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/actiontargets', params=params, **kwargs)

    def get_journey_actiontarget(self, action_target_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/actiontargets/{quote(str(action_target_id), safe='')}", params=params, **kwargs)

    def get_journey_actiontemplates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/actiontemplates', params=params, **kwargs)

    def post_journey_actiontemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/actiontemplates', params=params, body=body, **kwargs)

    def delete_journey_actiontemplate(self, action_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/actiontemplates/{quote(str(action_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_actiontemplate(self, action_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/actiontemplates/{quote(str(action_template_id), safe='')}", params=params, **kwargs)

    def patch_journey_actiontemplate(self, action_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/actiontemplates/{quote(str(action_template_id), safe='')}", params=params, body=body, **kwargs)

    def post_journey_deployment_actionevent(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/deployments/{quote(str(deployment_id), safe='')}/actionevent", params=params, body=body, **kwargs)

    def post_journey_deployment_appevents(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/deployments/{quote(str(deployment_id), safe='')}/appevents", params=params, body=body, **kwargs)

    def get_journey_deployment_customer_ping(self, customer_cookie_id, deployment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/deployments/{quote(str(deployment_id), safe='')}/customers/{quote(str(customer_cookie_id), safe='')}/ping", params=params, **kwargs)

    def post_journey_deployment_webevents(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/deployments/{quote(str(deployment_id), safe='')}/webevents", params=params, body=body, **kwargs)

    def get_journey_externalevents_configurations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/externalevents/configurations', params=params, **kwargs)

    def post_journey_externalevents_configurations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/externalevents/configurations', params=params, body=body, **kwargs)

    def delete_journey_externalevents_configuration(self, config_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/externalevents/configurations/{quote(str(config_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_externalevents_configuration(self, config_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/externalevents/configurations/{quote(str(config_id), safe='')}", params=params, **kwargs)

    def patch_journey_externalevents_configuration(self, config_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/externalevents/configurations/{quote(str(config_id), safe='')}", params=params, body=body, **kwargs)

    def post_journey_externalevents_configuration_events(self, configuration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/externalevents/configurations/{quote(str(configuration_id), safe='')}/events", params=params, body=body, **kwargs)

    def get_journey_externalevents_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/externalevents/schemas', params=params, **kwargs)

    def post_journey_externalevents_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/externalevents/schemas', params=params, body=body, **kwargs)

    def get_journey_externalevents_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/externalevents/schemas/coretypes', params=params, **kwargs)

    def get_journey_externalevents_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/externalevents/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_journey_externalevents_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/externalevents/schemas/limits', params=params, **kwargs)

    def delete_journey_externalevents_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/externalevents/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_externalevents_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/externalevents/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_journey_externalevents_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/journey/externalevents/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_externalevents_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/externalevents/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_journey_externalevents_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/externalevents/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def post_journey_flows_paths_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/flows/paths/query', params=params, body=body, **kwargs)

    def get_journey_outcomes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/outcomes', params=params, **kwargs)

    def post_journey_outcomes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/outcomes', params=params, body=body, **kwargs)

    def get_journey_outcomes_predictors(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/outcomes/predictors', params=params, **kwargs)

    def post_journey_outcomes_predictors(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/outcomes/predictors', params=params, body=body, **kwargs)

    def delete_journey_outcomes_predictor(self, predictor_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/outcomes/predictors/{quote(str(predictor_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_outcomes_predictor(self, predictor_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/outcomes/predictors/{quote(str(predictor_id), safe='')}", params=params, **kwargs)

    def delete_journey_outcome(self, outcome_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/outcomes/{quote(str(outcome_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_outcome(self, outcome_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/outcomes/{quote(str(outcome_id), safe='')}", params=params, **kwargs)

    def patch_journey_outcome(self, outcome_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/outcomes/{quote(str(outcome_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_segments(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/segments', params=params, **kwargs)

    def post_journey_segments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/segments', params=params, body=body, **kwargs)

    def delete_journey_segment(self, segment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/segments/{quote(str(segment_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_segment(self, segment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/segments/{quote(str(segment_id), safe='')}", params=params, **kwargs)

    def patch_journey_segment(self, segment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/segments/{quote(str(segment_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_session(self, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/sessions/{quote(str(session_id), safe='')}", params=params, **kwargs)

    def get_journey_session_events(self, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/sessions/{quote(str(session_id), safe='')}/events", params=params, **kwargs)

    def get_journey_session_outcomescores(self, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/sessions/{quote(str(session_id), safe='')}/outcomescores", params=params, **kwargs)

    def get_journey_views(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views', params=params, **kwargs)

    def post_journey_views(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/views', params=params, body=body, **kwargs)

    def get_journey_views_data_details(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/data/details', params=params, **kwargs)

    def post_journey_views_encodings_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/journey/views/encodings/validate', params=params, body=body, **kwargs)

    def get_journey_views_eventdefinitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/eventdefinitions', params=params, **kwargs)

    def get_journey_views_eventdefinitions_external(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/eventdefinitions/external', params=params, **kwargs)

    def get_journey_views_eventdefinitions_external_changes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/eventdefinitions/external/changes', params=params, **kwargs)

    def get_journey_views_eventdefinition(self, event_definition_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/eventdefinitions/{quote(str(event_definition_id), safe='')}", params=params, **kwargs)

    def put_journey_views_eventdefinition(self, event_definition_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/journey/views/eventdefinitions/{quote(str(event_definition_id), safe='')}", params=params, body=body, **kwargs)

    def put_journey_views_eventdefinition_activate(self, event_definition_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/journey/views/eventdefinitions/{quote(str(event_definition_id), safe='')}/activate", params=params, body=body, **kwargs)

    def get_journey_views_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/jobs', params=params, **kwargs)

    def get_journey_views_jobs_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/jobs/me', params=params, **kwargs)

    def get_journey_views_schedules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/journey/views/schedules', params=params, **kwargs)

    def delete_journey_view(self, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/views/{quote(str(view_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_view(self, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}", params=params, **kwargs)

    def delete_journey_view_schedules(self, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/schedules", params=params, body=body, **kwargs)

    def get_journey_view_schedules(self, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/schedules", params=params, **kwargs)

    def post_journey_view_schedules(self, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/schedules", params=params, body=body, **kwargs)

    def put_journey_view_schedules(self, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/schedules", params=params, body=body, **kwargs)

    def post_journey_view_versions(self, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions", params=params, body=body, **kwargs)

    def post_journey_view_version_jobs(self, journey_version_id, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_version_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_journey_view_version_jobs_latest(self, journey_version_id, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_version_id), safe='')}/jobs/latest", params=params, **kwargs)

    def get_journey_view_version_job(self, job_id, journey_version_id, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_version_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def patch_journey_view_version_job(self, job_id, journey_version_id, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_version_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_journey_view_version_job_results_chart(self, chart_id, job_id, journey_version_id, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_version_id), safe='')}/jobs/{quote(str(job_id), safe='')}/results/charts/{quote(str(chart_id), safe='')}", params=params, **kwargs)

    def get_journey_view_version_chart(self, chart_id, journey_view_version, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_view_version), safe='')}/charts/{quote(str(chart_id), safe='')}", params=params, **kwargs)

    def get_journey_view_version_chart_version(self, chart_id, chart_version, journey_view_version, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_view_version), safe='')}/charts/{quote(str(chart_id), safe='')}/versions/{quote(str(chart_version), safe='')}", params=params, **kwargs)

    def get_journey_view_version_job_results(self, job_id, journey_view_version, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(journey_view_version), safe='')}/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def get_journey_view_version(self, version_id, view_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def put_journey_view_version(self, version_id, view_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/journey/views/{quote(str(view_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_connections(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/knowledge/connections', params=params, **kwargs)

    def post_knowledge_connections(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/connections', params=params, body=body, **kwargs)

    def delete_knowledge_connection(self, connection_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/connections/{quote(str(connection_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_connection(self, connection_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/connections/{quote(str(connection_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_connection(self, connection_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/connections/{quote(str(connection_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_connection_options(self, connection_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/connections/{quote(str(connection_id), safe='')}/options", params=params, **kwargs)

    def post_knowledge_documentuploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/documentuploads', params=params, body=body, **kwargs)

    def post_knowledge_guest_sessions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/guest/sessions', params=params, body=body, **kwargs)

    def get_knowledge_guest_session_categories(self, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/categories", params=params, **kwargs)

    def get_knowledge_guest_session_documents(self, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents", params=params, **kwargs)

    def post_knowledge_guest_session_documents_answers(self, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/answers", params=params, body=body, **kwargs)

    def post_knowledge_guest_session_documents_presentations(self, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/presentations", params=params, body=body, **kwargs)

    def post_knowledge_guest_session_documents_search(self, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/search", params=params, body=body, **kwargs)

    def post_knowledge_guest_session_documents_search_suggestions(self, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/search/suggestions", params=params, body=body, **kwargs)

    def patch_knowledge_guest_session_documents_search_search_id(self, search_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/search/{quote(str(search_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_guest_session_document(self, document_id, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/{quote(str(document_id), safe='')}", params=params, **kwargs)

    def post_knowledge_guest_session_document_copies(self, document_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/{quote(str(document_id), safe='')}/copies", params=params, body=body, **kwargs)

    def post_knowledge_guest_session_document_feedback(self, document_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/{quote(str(document_id), safe='')}/feedback", params=params, body=body, **kwargs)

    def post_knowledge_guest_session_document_views(self, document_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/guest/sessions/{quote(str(session_id), safe='')}/documents/{quote(str(document_id), safe='')}/views", params=params, body=body, **kwargs)

    def get_knowledge_integration_options(self, integration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/integrations/{quote(str(integration_id), safe='')}/options", params=params, **kwargs)

    def post_knowledge_knowledgebases(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/knowledgebases', params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_categories(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/categories", params=params, **kwargs)

    def post_knowledge_knowledgebase_categories(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/categories", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_category(self, category_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_category(self, category_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/categories/{quote(str(category_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_category(self, category_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_chunks_search(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/chunks/search", params=params, body=body, **kwargs)

    def patch_knowledge_knowledgebase_chunks_search_search_id(self, knowledge_base_id, search_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/chunks/search/{quote(str(search_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_documents(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents", params=params, **kwargs)

    def post_knowledge_knowledgebase_documents(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_answers(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/answers", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_bulk_remove(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/bulk/remove", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_bulk_update(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/bulk/update", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_documents_feedback(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/feedback", params=params, **kwargs)

    def post_knowledge_knowledgebase_documents_presentations(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/presentations", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_query(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/query", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_search(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/search", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_search_suggestions(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/search/suggestions", params=params, body=body, **kwargs)

    def patch_knowledge_knowledgebase_documents_search_search_id(self, knowledge_base_id, search_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/search/{quote(str(search_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_documents_versions_bulk_add(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/versions/bulk/add", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_document(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document(self, document_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_document(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_document_copies(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/copies", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_feedback(self, document_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/feedback", params=params, **kwargs)

    def post_knowledge_knowledgebase_document_feedback(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/feedback", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_feedback_feedback_id(self, document_id, feedback_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/feedback/{quote(str(feedback_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_document_feedback_feedback_id(self, document_id, feedback_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/feedback/{quote(str(feedback_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_variations(self, document_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/variations", params=params, **kwargs)

    def post_knowledge_knowledgebase_document_variations(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/variations", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_document_variation(self, document_id, document_variation_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/variations/{quote(str(document_variation_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_variation(self, document_id, document_variation_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/variations/{quote(str(document_variation_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_document_variation(self, document_id, document_variation_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/variations/{quote(str(document_variation_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_versions(self, document_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/versions", params=params, **kwargs)

    def post_knowledge_knowledgebase_document_versions(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/versions", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_document_version(self, document_id, knowledge_base_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def get_knowledge_knowledgebase_document_version_variations(self, document_id, knowledge_base_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/versions/{quote(str(version_id), safe='')}/variations", params=params, **kwargs)

    def get_knowledge_knowledgebase_document_version_variation(self, document_id, knowledge_base_id, variation_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/versions/{quote(str(version_id), safe='')}/variations/{quote(str(variation_id), safe='')}", params=params, **kwargs)

    def post_knowledge_knowledgebase_document_views(self, document_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/documents/{quote(str(document_id), safe='')}/views", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_export_jobs(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/export/jobs", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_export_job(self, export_job_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/export/jobs/{quote(str(export_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_export_job(self, export_job_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/export/jobs/{quote(str(export_job_id), safe='')}", params=params, **kwargs)

    def post_knowledge_knowledgebase_import_jobs(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/import/jobs", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_import_job(self, import_job_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/import/jobs/{quote(str(import_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_import_job(self, import_job_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/import/jobs/{quote(str(import_job_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_import_job(self, import_job_id, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/import/jobs/{quote(str(import_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_labels(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/labels", params=params, **kwargs)

    def post_knowledge_knowledgebase_labels(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/labels", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_label(self, knowledge_base_id, label_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/labels/{quote(str(label_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_label(self, knowledge_base_id, label_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/labels/{quote(str(label_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_label(self, knowledge_base_id, label_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/labels/{quote(str(label_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_operations(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/operations", params=params, **kwargs)

    def get_knowledge_knowledgebase_operations_users_query(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/operations/users/query", params=params, **kwargs)

    def post_knowledge_knowledgebase_parse_jobs(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/parse/jobs", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_parse_job(self, knowledge_base_id, parse_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/parse/jobs/{quote(str(parse_job_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_parse_job(self, knowledge_base_id, parse_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/parse/jobs/{quote(str(parse_job_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_parse_job_import(self, knowledge_base_id, parse_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/parse/jobs/{quote(str(parse_job_id), safe='')}/import", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_sources(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources", params=params, **kwargs)

    def post_knowledge_knowledgebase_sources_salesforce(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/salesforce", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_sources_salesforce_source_id(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/salesforce/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_sources_salesforce_source_id(self, knowledge_base_id, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/salesforce/{quote(str(source_id), safe='')}", params=params, **kwargs)

    def put_knowledge_knowledgebase_sources_salesforce_source_id(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/salesforce/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_sources_salesforce_source_id_sync(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/salesforce/{quote(str(source_id), safe='')}/sync", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_sources_servicenow(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/servicenow", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_sources_servicenow_source_id(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/servicenow/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_sources_servicenow_source_id(self, knowledge_base_id, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/servicenow/{quote(str(source_id), safe='')}", params=params, **kwargs)

    def put_knowledge_knowledgebase_sources_servicenow_source_id(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/servicenow/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_sources_servicenow_source_id_sync(self, knowledge_base_id, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/sources/servicenow/{quote(str(source_id), safe='')}/sync", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_synchronize_jobs(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/synchronize/jobs", params=params, body=body, **kwargs)

    def delete_knowledge_knowledgebase_synchronize_job(self, knowledge_base_id, sync_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/synchronize/jobs/{quote(str(sync_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_synchronize_job(self, knowledge_base_id, sync_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/synchronize/jobs/{quote(str(sync_job_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_synchronize_job(self, knowledge_base_id, sync_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/synchronize/jobs/{quote(str(sync_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_unanswered_groups(self, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/unanswered/groups", params=params, **kwargs)

    def get_knowledge_knowledgebase_unanswered_group(self, group_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/unanswered/groups/{quote(str(group_id), safe='')}", params=params, **kwargs)

    def get_knowledge_knowledgebase_unanswered_group_phrasegroup(self, group_id, knowledge_base_id, phrase_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/unanswered/groups/{quote(str(group_id), safe='')}/phrasegroups/{quote(str(phrase_group_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_knowledgebase_unanswered_group_phrasegroup(self, group_id, knowledge_base_id, phrase_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/unanswered/groups/{quote(str(group_id), safe='')}/phrasegroups/{quote(str(phrase_group_id), safe='')}", params=params, body=body, **kwargs)

    def post_knowledge_knowledgebase_uploads_urls_jobs(self, knowledge_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/uploads/urls/jobs", params=params, body=body, **kwargs)

    def get_knowledge_knowledgebase_uploads_urls_job(self, job_id, knowledge_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/knowledgebases/{quote(str(knowledge_base_id), safe='')}/uploads/urls/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_knowledge_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/search', params=params, body=body, **kwargs)

    def post_knowledge_search_preview(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/search/preview', params=params, body=body, **kwargs)

    def get_knowledge_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/knowledge/settings', params=params, **kwargs)

    def post_knowledge_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/settings', params=params, body=body, **kwargs)

    def delete_knowledge_setting(self, knowledge_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/settings/{quote(str(knowledge_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_setting(self, knowledge_setting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/settings/{quote(str(knowledge_setting_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_setting(self, knowledge_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/settings/{quote(str(knowledge_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_sources(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/knowledge/sources', params=params, **kwargs)

    def post_knowledge_sources(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/knowledge/sources', params=params, body=body, **kwargs)

    def get_knowledge_sources_synchronizations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/knowledge/sources/synchronizations', params=params, **kwargs)

    def delete_knowledge_source(self, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_source(self, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}", params=params, **kwargs)

    def put_knowledge_source(self, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_source_synchronizations(self, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations", params=params, **kwargs)

    def post_knowledge_source_synchronizations(self, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations", params=params, body=body, **kwargs)

    def get_knowledge_source_synchronization(self, source_id, synchronization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}", params=params, **kwargs)

    def patch_knowledge_source_synchronization(self, source_id, synchronization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_source_synchronization_deletions(self, source_id, synchronization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/deletions", params=params, **kwargs)

    def post_knowledge_source_synchronization_deletions(self, source_id, synchronization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/deletions", params=params, body=body, **kwargs)

    def delete_knowledge_source_synchronization_deletion(self, file_id, source_id, synchronization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/deletions/{quote(str(file_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_source_synchronization_deletion(self, file_id, source_id, synchronization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/deletions/{quote(str(file_id), safe='')}", params=params, **kwargs)

    def get_knowledge_source_synchronization_uploads(self, source_id, synchronization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/uploads", params=params, **kwargs)

    def post_knowledge_source_synchronization_uploads(self, source_id, synchronization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/uploads", params=params, body=body, **kwargs)

    def delete_knowledge_source_synchronization_upload(self, file_id, source_id, synchronization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/uploads/{quote(str(file_id), safe='')}", params=params, body=body, **kwargs)

    def get_knowledge_source_synchronization_upload(self, file_id, source_id, synchronization_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/knowledge/sources/{quote(str(source_id), safe='')}/synchronizations/{quote(str(synchronization_id), safe='')}/uploads/{quote(str(file_id), safe='')}", params=params, **kwargs)

    def get_languages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languages', params=params, **kwargs)

    def post_languages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/languages', params=params, body=body, **kwargs)

    def get_languages_translations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languages/translations', params=params, **kwargs)

    def get_languages_translations_builtin(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languages/translations/builtin', params=params, **kwargs)

    def get_languages_translations_organization(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languages/translations/organization', params=params, **kwargs)

    def get_languages_translations_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languages/translations/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def delete_language(self, language_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languages/{quote(str(language_id), safe='')}", params=params, body=body, **kwargs)

    def get_language(self, language_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languages/{quote(str(language_id), safe='')}", params=params, **kwargs)

    def get_languageunderstanding_domains(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languageunderstanding/domains', params=params, **kwargs)

    def post_languageunderstanding_domains(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/languageunderstanding/domains', params=params, body=body, **kwargs)

    def delete_languageunderstanding_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_domain(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}", params=params, **kwargs)

    def patch_languageunderstanding_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_domain_feedback(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/feedback", params=params, **kwargs)

    def post_languageunderstanding_domain_feedback(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/feedback", params=params, body=body, **kwargs)

    def delete_languageunderstanding_domain_feedback_feedback_id(self, domain_id, feedback_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/feedback/{quote(str(feedback_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_domain_feedback_feedback_id(self, domain_id, feedback_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/feedback/{quote(str(feedback_id), safe='')}", params=params, **kwargs)

    def get_languageunderstanding_domain_versions(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions", params=params, **kwargs)

    def post_languageunderstanding_domain_versions(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions", params=params, body=body, **kwargs)

    def delete_languageunderstanding_domain_version(self, domain_id, domain_version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_domain_version(self, domain_id, domain_version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}", params=params, **kwargs)

    def put_languageunderstanding_domain_version(self, domain_id, domain_version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}", params=params, body=body, **kwargs)

    def post_languageunderstanding_domain_version_detect(self, domain_id, domain_version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}/detect", params=params, body=body, **kwargs)

    def post_languageunderstanding_domain_version_publish(self, domain_id, domain_version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}/publish", params=params, body=body, **kwargs)

    def get_languageunderstanding_domain_version_report(self, domain_id, domain_version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}/report", params=params, **kwargs)

    def post_languageunderstanding_domain_version_train(self, domain_id, domain_version_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/domains/{quote(str(domain_id), safe='')}/versions/{quote(str(domain_version_id), safe='')}/train", params=params, body=body, **kwargs)

    def get_languageunderstanding_ignorephrase(self, language_code, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/ignorephrases/{quote(str(language_code), safe='')}", params=params, **kwargs)

    def post_languageunderstanding_ignorephrase(self, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/ignorephrases/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def post_languageunderstanding_ignorephrase_remove(self, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/ignorephrases/{quote(str(language_code), safe='')}/remove", params=params, body=body, **kwargs)

    def get_languageunderstanding_ignoretopic(self, language_code, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/ignoretopics/{quote(str(language_code), safe='')}", params=params, **kwargs)

    def post_languageunderstanding_ignoretopic(self, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/ignoretopics/{quote(str(language_code), safe='')}", params=params, body=body, **kwargs)

    def post_languageunderstanding_ignoretopic_remove(self, language_code, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/ignoretopics/{quote(str(language_code), safe='')}/remove", params=params, body=body, **kwargs)

    def get_languageunderstanding_miners(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languageunderstanding/miners', params=params, **kwargs)

    def post_languageunderstanding_miners(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/languageunderstanding/miners', params=params, body=body, **kwargs)

    def delete_languageunderstanding_miner(self, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_miner(self, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}", params=params, **kwargs)

    def get_languageunderstanding_miner_drafts(self, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/drafts", params=params, **kwargs)

    def post_languageunderstanding_miner_drafts(self, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/drafts", params=params, body=body, **kwargs)

    def delete_languageunderstanding_miner_draft(self, draft_id, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/drafts/{quote(str(draft_id), safe='')}", params=params, body=body, **kwargs)

    def get_languageunderstanding_miner_draft(self, draft_id, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/drafts/{quote(str(draft_id), safe='')}", params=params, **kwargs)

    def patch_languageunderstanding_miner_draft(self, draft_id, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/drafts/{quote(str(draft_id), safe='')}", params=params, body=body, **kwargs)

    def post_languageunderstanding_miner_execute(self, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/execute", params=params, body=body, **kwargs)

    def get_languageunderstanding_miner_intents(self, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/intents", params=params, **kwargs)

    def get_languageunderstanding_miner_intent(self, intent_id, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/intents/{quote(str(intent_id), safe='')}", params=params, **kwargs)

    def get_languageunderstanding_miner_topics(self, miner_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/topics", params=params, **kwargs)

    def get_languageunderstanding_miner_topic(self, miner_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/topics/{quote(str(topic_id), safe='')}", params=params, **kwargs)

    def get_languageunderstanding_miner_topic_phrase(self, miner_id, phrase_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/topics/{quote(str(topic_id), safe='')}/phrases/{quote(str(phrase_id), safe='')}", params=params, **kwargs)

    def post_languageunderstanding_miner_uploads(self, miner_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/languageunderstanding/miners/{quote(str(miner_id), safe='')}/uploads", params=params, body=body, **kwargs)

    def get_languageunderstanding_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/languageunderstanding/settings', params=params, **kwargs)

    def post_learning_assessments_scoring(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/assessments/scoring', params=params, body=body, **kwargs)

    def get_learning_assignments(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/learning/assignments', params=params, **kwargs)

    def post_learning_assignments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/assignments', params=params, body=body, **kwargs)

    def post_learning_assignments_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/assignments/aggregates/query', params=params, body=body, **kwargs)

    def post_learning_assignments_bulkadd(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/assignments/bulkadd', params=params, body=body, **kwargs)

    def post_learning_assignments_bulkremove(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/assignments/bulkremove', params=params, body=body, **kwargs)

    def get_learning_assignments_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/learning/assignments/me', params=params, **kwargs)

    def delete_learning_assignment(self, assignment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}", params=params, body=body, **kwargs)

    def get_learning_assignment(self, assignment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}", params=params, **kwargs)

    def patch_learning_assignment(self, assignment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}", params=params, body=body, **kwargs)

    def post_learning_assignment_reassign(self, assignment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}/reassign", params=params, body=body, **kwargs)

    def patch_learning_assignment_reschedule(self, assignment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}/reschedule", params=params, body=body, **kwargs)

    def post_learning_assignment_reset(self, assignment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}/reset", params=params, body=body, **kwargs)

    def get_learning_assignment_step(self, assignment_id, step_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}/steps/{quote(str(step_id), safe='')}", params=params, **kwargs)

    def patch_learning_assignment_step(self, assignment_id, step_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/learning/assignments/{quote(str(assignment_id), safe='')}/steps/{quote(str(step_id), safe='')}", params=params, body=body, **kwargs)

    def get_learning_modules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/learning/modules', params=params, **kwargs)

    def post_learning_modules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/modules', params=params, body=body, **kwargs)

    def get_learning_modules_assignments(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/learning/modules/assignments', params=params, **kwargs)

    def get_learning_modules_coverart_cover_art_id(self, cover_art_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/coverart/{quote(str(cover_art_id), safe='')}", params=params, **kwargs)

    def delete_learning_module(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}", params=params, body=body, **kwargs)

    def get_learning_module(self, module_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}", params=params, **kwargs)

    def put_learning_module(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}", params=params, body=body, **kwargs)

    def post_learning_module_jobs(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_learning_module_job(self, job_id, module_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_learning_module_preview(self, module_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/preview", params=params, **kwargs)

    def put_learning_module_preview(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/preview", params=params, body=body, **kwargs)

    def post_learning_module_publish(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/publish", params=params, body=body, **kwargs)

    def get_learning_module_rule(self, module_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/rule", params=params, **kwargs)

    def put_learning_module_rule(self, module_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/rule", params=params, body=body, **kwargs)

    def patch_learning_module_user_assignments(self, module_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/users/{quote(str(user_id), safe='')}/assignments", params=params, body=body, **kwargs)

    def get_learning_module_version(self, module_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/modules/{quote(str(module_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def post_learning_rules_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/rules/query', params=params, body=body, **kwargs)

    def post_learning_scheduleslots_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/scheduleslots/jobs', params=params, body=body, **kwargs)

    def get_learning_scheduleslots_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/scheduleslots/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_learning_scheduleslots_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/scheduleslots/query', params=params, body=body, **kwargs)

    def post_learning_scorm(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/learning/scorm', params=params, body=body, **kwargs)

    def get_learning_scorm_scorm_id(self, scorm_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/learning/scorm/{quote(str(scorm_id), safe='')}", params=params, **kwargs)

    def get_license_definitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/license/definitions', params=params, **kwargs)

    def get_license_definition(self, license_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/license/definitions/{quote(str(license_id), safe='')}", params=params, **kwargs)

    def post_license_infer(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/license/infer', params=params, body=body, **kwargs)

    def post_license_organization(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/license/organization', params=params, body=body, **kwargs)

    def get_license_toggle(self, feature_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/license/toggles/{quote(str(feature_name), safe='')}", params=params, **kwargs)

    def post_license_toggle(self, feature_name, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/license/toggles/{quote(str(feature_name), safe='')}", params=params, body=body, **kwargs)

    def get_license_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/license/users', params=params, **kwargs)

    def post_license_users(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/license/users', params=params, body=body, **kwargs)

    def get_license_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/license/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def get_locations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/locations', params=params, **kwargs)

    def post_locations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/locations', params=params, body=body, **kwargs)

    def get_locations_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/locations/search', params=params, **kwargs)

    def post_locations_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/locations/search', params=params, body=body, **kwargs)

    def delete_location(self, location_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/locations/{quote(str(location_id), safe='')}", params=params, body=body, **kwargs)

    def get_location(self, location_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/locations/{quote(str(location_id), safe='')}", params=params, **kwargs)

    def patch_location(self, location_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/locations/{quote(str(location_id), safe='')}", params=params, body=body, **kwargs)

    def get_location_sublocations(self, location_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/locations/{quote(str(location_id), safe='')}/sublocations", params=params, **kwargs)

    def get_messaging_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/messaging/settings', params=params, **kwargs)

    def post_messaging_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/messaging/settings', params=params, body=body, **kwargs)

    def delete_messaging_settings_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/messaging/settings/default', params=params, body=body, **kwargs)

    def get_messaging_settings_default(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/messaging/settings/default', params=params, **kwargs)

    def put_messaging_settings_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/messaging/settings/default', params=params, body=body, **kwargs)

    def delete_messaging_setting(self, message_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_messaging_setting(self, message_setting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, **kwargs)

    def patch_messaging_setting(self, message_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/messaging/settings/{quote(str(message_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_messaging_supportedcontent(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/messaging/supportedcontent', params=params, **kwargs)

    def post_messaging_supportedcontent(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/messaging/supportedcontent', params=params, body=body, **kwargs)

    def delete_messaging_supportedcontent_supported_content_id(self, supported_content_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, body=body, **kwargs)

    def get_messaging_supportedcontent_supported_content_id(self, supported_content_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, **kwargs)

    def patch_messaging_supportedcontent_supported_content_id(self, supported_content_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/messaging/supportedcontent/{quote(str(supported_content_id), safe='')}", params=params, body=body, **kwargs)

    def delete_notifications_channel_subscriptions(self, channel_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/notifications/channels/{quote(str(channel_id), safe='')}/subscriptions", params=params, body=body, **kwargs)

    def get_notifications_channel_subscriptions(self, channel_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/notifications/channels/{quote(str(channel_id), safe='')}/subscriptions", params=params, **kwargs)

    def put_notifications_channel_subscriptions(self, channel_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/notifications/channels/{quote(str(channel_id), safe='')}/subscriptions", params=params, body=body, **kwargs)

    def get_oauth_authorizations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/oauth/authorizations', params=params, **kwargs)

    def get_oauth_authorization(self, client_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/oauth/authorizations/{quote(str(client_id), safe='')}", params=params, **kwargs)

    def post_oauth_clients(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/oauth/clients', params=params, body=body, **kwargs)

    def delete_oauth_client(self, client_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}", params=params, body=body, **kwargs)

    def get_oauth_client(self, client_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}", params=params, **kwargs)

    def put_oauth_client(self, client_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}", params=params, body=body, **kwargs)

    def post_oauth_client_secret(self, client_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}/secret", params=params, body=body, **kwargs)

    def post_oauth_client_usage_query(self, client_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}/usage/query", params=params, body=body, **kwargs)

    def get_oauth_client_usage_query_result(self, client_id, execution_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}/usage/query/results/{quote(str(execution_id), safe='')}", params=params, **kwargs)

    def get_oauth_client_usage_summary(self, client_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/oauth/clients/{quote(str(client_id), safe='')}/usage/summary", params=params, **kwargs)

    def get_oauth_scopes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/oauth/scopes', params=params, **kwargs)

    def get_oauth_scope(self, scope_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/oauth/scopes/{quote(str(scope_id), safe='')}", params=params, **kwargs)

    def get_organizations_authentication_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/authentication/settings', params=params, **kwargs)

    def patch_organizations_authentication_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/organizations/authentication/settings', params=params, body=body, **kwargs)

    def get_organizations_embeddedintegration(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/embeddedintegration', params=params, **kwargs)

    def put_organizations_embeddedintegration(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/organizations/embeddedintegration', params=params, body=body, **kwargs)

    def patch_organizations_feature(self, feature_name, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/organizations/features/{quote(str(feature_name), safe='')}", params=params, body=body, **kwargs)

    def get_organizations_ipaddressauthentication(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/ipaddressauthentication', params=params, **kwargs)

    def put_organizations_ipaddressauthentication(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/organizations/ipaddressauthentication', params=params, body=body, **kwargs)

    def get_organizations_limits_changerequests(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/limits/changerequests', params=params, **kwargs)

    def get_organizations_limits_changerequest(self, request_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/organizations/limits/changerequests/{quote(str(request_id), safe='')}", params=params, **kwargs)

    def get_organizations_limits_docs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/limits/docs', params=params, **kwargs)

    def get_organizations_limits_docs_freetrial(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/limits/docs/freetrial', params=params, **kwargs)

    def get_organizations_limits_namespaces(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/limits/namespaces', params=params, **kwargs)

    def get_organizations_limits_namespace(self, namespace_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/organizations/limits/namespaces/{quote(str(namespace_name), safe='')}", params=params, **kwargs)

    def get_organizations_limits_namespace_defaults(self, namespace_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/organizations/limits/namespaces/{quote(str(namespace_name), safe='')}/defaults", params=params, **kwargs)

    def put_organizations_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/organizations/me', params=params, body=body, **kwargs)

    def get_organizations_whitelist(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/organizations/whitelist', params=params, **kwargs)

    def put_organizations_whitelist(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/organizations/whitelist', params=params, body=body, **kwargs)

    def post_orgauthorization_pairings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/pairings', params=params, body=body, **kwargs)

    def get_orgauthorization_pairing(self, pairing_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/pairings/{quote(str(pairing_id), safe='')}", params=params, **kwargs)

    def get_orgauthorization_trustees(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/orgauthorization/trustees', params=params, **kwargs)

    def post_orgauthorization_trustees(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/trustees', params=params, body=body, **kwargs)

    def post_orgauthorization_trustees_audits(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/trustees/audits', params=params, body=body, **kwargs)

    def get_orgauthorization_trustees_care(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/orgauthorization/trustees/care', params=params, **kwargs)

    def post_orgauthorization_trustees_care(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/trustees/care', params=params, body=body, **kwargs)

    def get_orgauthorization_trustees_default(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/orgauthorization/trustees/default', params=params, **kwargs)

    def post_orgauthorization_trustees_default(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/trustees/default', params=params, body=body, **kwargs)

    def delete_orgauthorization_trustee(self, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee(self, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustee(self, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_clonedusers(self, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/clonedusers", params=params, **kwargs)

    def delete_orgauthorization_trustee_cloneduser(self, trustee_org_id, trustee_user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/clonedusers/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_groups(self, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups", params=params, **kwargs)

    def post_orgauthorization_trustee_groups(self, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups", params=params, body=body, **kwargs)

    def delete_orgauthorization_trustee_group(self, trustee_group_id, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_group(self, trustee_group_id, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustee_group_roledivisions(self, trustee_group_id, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}/roledivisions", params=params, body=body, **kwargs)

    def delete_orgauthorization_trustee_group_roles(self, trustee_group_id, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}/roles", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_group_roles(self, trustee_group_id, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}/roles", params=params, **kwargs)

    def put_orgauthorization_trustee_group_roles(self, trustee_group_id, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/groups/{quote(str(trustee_group_id), safe='')}/roles", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_users(self, trustee_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users", params=params, **kwargs)

    def post_orgauthorization_trustee_users(self, trustee_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users", params=params, body=body, **kwargs)

    def delete_orgauthorization_trustee_user(self, trustee_org_id, trustee_user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_user(self, trustee_org_id, trustee_user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustee_user_roledivisions(self, trustee_org_id, trustee_user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}/roledivisions", params=params, body=body, **kwargs)

    def delete_orgauthorization_trustee_user_roles(self, trustee_org_id, trustee_user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}/roles", params=params, body=body, **kwargs)

    def get_orgauthorization_trustee_user_roles(self, trustee_org_id, trustee_user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}/roles", params=params, **kwargs)

    def put_orgauthorization_trustee_user_roles(self, trustee_org_id, trustee_user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustees/{quote(str(trustee_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}/roles", params=params, body=body, **kwargs)

    def post_orgauthorization_trustor_audits(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/orgauthorization/trustor/audits', params=params, body=body, **kwargs)

    def get_orgauthorization_trustors(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/orgauthorization/trustors', params=params, **kwargs)

    def delete_orgauthorization_trustor(self, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor(self, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}", params=params, **kwargs)

    def get_orgauthorization_trustor_clonedusers(self, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/clonedusers", params=params, **kwargs)

    def delete_orgauthorization_trustor_cloneduser(self, trustee_user_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/clonedusers/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor_cloneduser(self, trustee_user_id, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/clonedusers/{quote(str(trustee_user_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustor_cloneduser(self, trustee_user_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/clonedusers/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor_groups(self, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/groups", params=params, **kwargs)

    def delete_orgauthorization_trustor_group(self, trustor_group_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/groups/{quote(str(trustor_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor_group(self, trustor_group_id, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/groups/{quote(str(trustor_group_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustor_group(self, trustor_group_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/groups/{quote(str(trustor_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor_users(self, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/users", params=params, **kwargs)

    def delete_orgauthorization_trustor_user(self, trustee_user_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orgauthorization_trustor_user(self, trustee_user_id, trustor_org_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}", params=params, **kwargs)

    def put_orgauthorization_trustor_user(self, trustee_user_id, trustor_org_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orgauthorization/trustors/{quote(str(trustor_org_id), safe='')}/users/{quote(str(trustee_user_id), safe='')}", params=params, body=body, **kwargs)

    def get_orphanrecordings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/orphanrecordings', params=params, **kwargs)

    def delete_orphanrecording(self, orphan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/orphanrecordings/{quote(str(orphan_id), safe='')}", params=params, body=body, **kwargs)

    def get_orphanrecording(self, orphan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orphanrecordings/{quote(str(orphan_id), safe='')}", params=params, **kwargs)

    def put_orphanrecording(self, orphan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/orphanrecordings/{quote(str(orphan_id), safe='')}", params=params, body=body, **kwargs)

    def get_orphanrecording_media(self, orphan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/orphanrecordings/{quote(str(orphan_id), safe='')}/media", params=params, **kwargs)

    def get_outbound_attemptlimits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/attemptlimits', params=params, **kwargs)

    def post_outbound_attemptlimits(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/attemptlimits', params=params, body=body, **kwargs)

    def delete_outbound_attemptlimit(self, attempt_limits_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/attemptlimits/{quote(str(attempt_limits_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_attemptlimit(self, attempt_limits_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/attemptlimits/{quote(str(attempt_limits_id), safe='')}", params=params, **kwargs)

    def put_outbound_attemptlimit(self, attempt_limits_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/attemptlimits/{quote(str(attempt_limits_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_callabletimesets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/callabletimesets', params=params, **kwargs)

    def post_outbound_callabletimesets(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/callabletimesets', params=params, body=body, **kwargs)

    def delete_outbound_callabletimeset(self, callable_time_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/callabletimesets/{quote(str(callable_time_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_callabletimeset(self, callable_time_set_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/callabletimesets/{quote(str(callable_time_set_id), safe='')}", params=params, **kwargs)

    def put_outbound_callabletimeset(self, callable_time_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/callabletimesets/{quote(str(callable_time_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_callanalysisresponsesets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/callanalysisresponsesets', params=params, **kwargs)

    def post_outbound_callanalysisresponsesets(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/callanalysisresponsesets', params=params, body=body, **kwargs)

    def delete_outbound_callanalysisresponseset(self, call_analysis_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/callanalysisresponsesets/{quote(str(call_analysis_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_callanalysisresponseset(self, call_analysis_set_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/callanalysisresponsesets/{quote(str(call_analysis_set_id), safe='')}", params=params, **kwargs)

    def put_outbound_callanalysisresponseset(self, call_analysis_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/callanalysisresponsesets/{quote(str(call_analysis_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_campaignrules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/campaignrules', params=params, **kwargs)

    def post_outbound_campaignrules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/campaignrules', params=params, body=body, **kwargs)

    def delete_outbound_campaignrule(self, campaign_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/campaignrules/{quote(str(campaign_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_campaignrule(self, campaign_rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaignrules/{quote(str(campaign_rule_id), safe='')}", params=params, **kwargs)

    def put_outbound_campaignrule(self, campaign_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/campaignrules/{quote(str(campaign_rule_id), safe='')}", params=params, body=body, **kwargs)

    def post_outbound_campaigns(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/campaigns', params=params, body=body, **kwargs)

    def get_outbound_campaigns_all(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/campaigns/all', params=params, **kwargs)

    def get_outbound_campaigns_all_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/campaigns/all/divisionviews', params=params, **kwargs)

    def get_outbound_campaigns_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/campaigns/divisionviews', params=params, **kwargs)

    def get_outbound_campaigns_divisionview(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/divisionviews/{quote(str(campaign_id), safe='')}", params=params, **kwargs)

    def post_outbound_campaigns_performance_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/campaigns/performance/query', params=params, body=body, **kwargs)

    def post_outbound_campaigns_progress(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/campaigns/progress', params=params, body=body, **kwargs)

    def delete_outbound_campaign(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_campaign(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}", params=params, **kwargs)

    def patch_outbound_campaign(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}", params=params, body=body, **kwargs)

    def put_outbound_campaign(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}", params=params, body=body, **kwargs)

    def post_outbound_campaign_agentownedmappingpreview(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/agentownedmappingpreview", params=params, body=body, **kwargs)

    def get_outbound_campaign_agentownedmappingpreview_results(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/agentownedmappingpreview/results", params=params, **kwargs)

    def put_outbound_campaign_agent(self, campaign_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/agents/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def post_outbound_campaign_callback_schedule(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/callback/schedule", params=params, body=body, **kwargs)

    def get_outbound_campaign_diagnostics(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/diagnostics", params=params, **kwargs)

    def get_outbound_campaign_interactions(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/interactions", params=params, **kwargs)

    def get_outbound_campaign_linedistribution(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/linedistribution", params=params, **kwargs)

    def delete_outbound_campaign_progress(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/progress", params=params, body=body, **kwargs)

    def get_outbound_campaign_progress(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/progress", params=params, **kwargs)

    def get_outbound_campaign_skillcombinations(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/skillcombinations", params=params, **kwargs)

    def post_outbound_campaign_start(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/start", params=params, body=body, **kwargs)

    def get_outbound_campaign_stats(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/stats", params=params, **kwargs)

    def post_outbound_campaign_stop(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/campaigns/{quote(str(campaign_id), safe='')}/stop", params=params, body=body, **kwargs)

    def get_outbound_contactlistfilters(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/contactlistfilters', params=params, **kwargs)

    def post_outbound_contactlistfilters(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlistfilters', params=params, body=body, **kwargs)

    def post_outbound_contactlistfilters_bulk_retrieve(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlistfilters/bulk/retrieve', params=params, body=body, **kwargs)

    def post_outbound_contactlistfilters_preview(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlistfilters/preview', params=params, body=body, **kwargs)

    def delete_outbound_contactlistfilter(self, contact_list_filter_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/contactlistfilters/{quote(str(contact_list_filter_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_contactlistfilter(self, contact_list_filter_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlistfilters/{quote(str(contact_list_filter_id), safe='')}", params=params, **kwargs)

    def put_outbound_contactlistfilter(self, contact_list_filter_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/contactlistfilters/{quote(str(contact_list_filter_id), safe='')}", params=params, body=body, **kwargs)

    def delete_outbound_contactlists(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/outbound/contactlists', params=params, body=body, **kwargs)

    def get_outbound_contactlists(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/contactlists', params=params, **kwargs)

    def post_outbound_contactlists(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlists', params=params, body=body, **kwargs)

    def post_outbound_contactlists_bulk_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlists/bulk/update', params=params, body=body, **kwargs)

    def get_outbound_contactlists_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/contactlists/divisionviews', params=params, **kwargs)

    def get_outbound_contactlists_divisionview(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/divisionviews/{quote(str(contact_list_id), safe='')}", params=params, **kwargs)

    def post_outbound_contactlists_uploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlists/uploads', params=params, body=body, **kwargs)

    def delete_outbound_contactlist(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_contactlist(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}", params=params, **kwargs)

    def put_outbound_contactlist(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}", params=params, body=body, **kwargs)

    def post_outbound_contactlist_clear(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/clear", params=params, body=body, **kwargs)

    def delete_outbound_contactlist_contacts(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts", params=params, body=body, **kwargs)

    def post_outbound_contactlist_contacts(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts", params=params, body=body, **kwargs)

    def post_outbound_contactlist_contacts_bulk(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/bulk", params=params, body=body, **kwargs)

    def get_outbound_contactlist_contacts_bulk_jobs(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/bulk/jobs", params=params, **kwargs)

    def get_outbound_contactlist_contacts_bulk_job(self, contact_list_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/bulk/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_outbound_contactlist_contacts_bulk_remove(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/bulk/remove", params=params, body=body, **kwargs)

    def post_outbound_contactlist_contacts_bulk_update(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/bulk/update", params=params, body=body, **kwargs)

    def post_outbound_contactlist_contacts_search(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/search", params=params, body=body, **kwargs)

    def delete_outbound_contactlist_contact(self, contact_id, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/{quote(str(contact_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_contactlist_contact(self, contact_id, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/{quote(str(contact_id), safe='')}", params=params, **kwargs)

    def put_outbound_contactlist_contact(self, contact_id, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/contacts/{quote(str(contact_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_contactlist_export(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/export", params=params, **kwargs)

    def post_outbound_contactlist_export(self, contact_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/export", params=params, body=body, **kwargs)

    def get_outbound_contactlist_importstatus(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/importstatus", params=params, **kwargs)

    def get_outbound_contactlist_timezonemappingpreview(self, contact_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlists/{quote(str(contact_list_id), safe='')}/timezonemappingpreview", params=params, **kwargs)

    def delete_outbound_contactlisttemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/outbound/contactlisttemplates', params=params, body=body, **kwargs)

    def get_outbound_contactlisttemplates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/contactlisttemplates', params=params, **kwargs)

    def post_outbound_contactlisttemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlisttemplates', params=params, body=body, **kwargs)

    def post_outbound_contactlisttemplates_bulk_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlisttemplates/bulk/add', params=params, body=body, **kwargs)

    def post_outbound_contactlisttemplates_bulk_retrieve(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/contactlisttemplates/bulk/retrieve', params=params, body=body, **kwargs)

    def delete_outbound_contactlisttemplate(self, contact_list_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/contactlisttemplates/{quote(str(contact_list_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_contactlisttemplate(self, contact_list_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/contactlisttemplates/{quote(str(contact_list_template_id), safe='')}", params=params, **kwargs)

    def put_outbound_contactlisttemplate(self, contact_list_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/contactlisttemplates/{quote(str(contact_list_template_id), safe='')}", params=params, body=body, **kwargs)

    def post_outbound_conversation_dnc(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/conversations/{quote(str(conversation_id), safe='')}/dnc", params=params, body=body, **kwargs)

    def get_outbound_diagnostics_campaign_summary(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/diagnostics/campaigns/{quote(str(campaign_id), safe='')}/summary", params=params, **kwargs)

    def get_outbound_digitalrulesets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/digitalrulesets', params=params, **kwargs)

    def post_outbound_digitalrulesets(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/digitalrulesets', params=params, body=body, **kwargs)

    def delete_outbound_digitalruleset(self, digital_rule_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/digitalrulesets/{quote(str(digital_rule_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_digitalruleset(self, digital_rule_set_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/digitalrulesets/{quote(str(digital_rule_set_id), safe='')}", params=params, **kwargs)

    def put_outbound_digitalruleset(self, digital_rule_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/digitalrulesets/{quote(str(digital_rule_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_dnclists(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/dnclists', params=params, **kwargs)

    def post_outbound_dnclists(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/dnclists', params=params, body=body, **kwargs)

    def get_outbound_dnclists_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/dnclists/divisionviews', params=params, **kwargs)

    def get_outbound_dnclists_divisionview(self, dnc_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/dnclists/divisionviews/{quote(str(dnc_list_id), safe='')}", params=params, **kwargs)

    def post_outbound_dnclists_uploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/dnclists/uploads', params=params, body=body, **kwargs)

    def delete_outbound_dnclist(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_dnclist(self, dnc_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}", params=params, **kwargs)

    def put_outbound_dnclist(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}", params=params, body=body, **kwargs)

    def delete_outbound_dnclist_customexclusioncolumns(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/customexclusioncolumns", params=params, body=body, **kwargs)

    def patch_outbound_dnclist_customexclusioncolumns(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/customexclusioncolumns", params=params, body=body, **kwargs)

    def delete_outbound_dnclist_emailaddresses(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/emailaddresses", params=params, body=body, **kwargs)

    def patch_outbound_dnclist_emailaddresses(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/emailaddresses", params=params, body=body, **kwargs)

    def post_outbound_dnclist_emailaddresses(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/emailaddresses", params=params, body=body, **kwargs)

    def get_outbound_dnclist_export(self, dnc_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/export", params=params, **kwargs)

    def post_outbound_dnclist_export(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/export", params=params, body=body, **kwargs)

    def get_outbound_dnclist_importstatus(self, dnc_list_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/importstatus", params=params, **kwargs)

    def delete_outbound_dnclist_phonenumbers(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/phonenumbers", params=params, body=body, **kwargs)

    def patch_outbound_dnclist_phonenumbers(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/phonenumbers", params=params, body=body, **kwargs)

    def post_outbound_dnclist_phonenumbers(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/phonenumbers", params=params, body=body, **kwargs)

    def delete_outbound_dnclist_whatsappnumbers(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/whatsappnumbers", params=params, body=body, **kwargs)

    def patch_outbound_dnclist_whatsappnumbers(self, dnc_list_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/outbound/dnclists/{quote(str(dnc_list_id), safe='')}/whatsappnumbers", params=params, body=body, **kwargs)

    def get_outbound_events(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/events', params=params, **kwargs)

    def get_outbound_event(self, event_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/events/{quote(str(event_id), safe='')}", params=params, **kwargs)

    def get_outbound_filespecificationtemplates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/filespecificationtemplates', params=params, **kwargs)

    def post_outbound_filespecificationtemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/filespecificationtemplates', params=params, body=body, **kwargs)

    def delete_outbound_filespecificationtemplates_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/outbound/filespecificationtemplates/bulk', params=params, body=body, **kwargs)

    def delete_outbound_filespecificationtemplate(self, file_specification_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/filespecificationtemplates/{quote(str(file_specification_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_filespecificationtemplate(self, file_specification_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/filespecificationtemplates/{quote(str(file_specification_template_id), safe='')}", params=params, **kwargs)

    def put_outbound_filespecificationtemplate(self, file_specification_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/filespecificationtemplates/{quote(str(file_specification_template_id), safe='')}", params=params, body=body, **kwargs)

    def delete_outbound_importtemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/outbound/importtemplates', params=params, body=body, **kwargs)

    def get_outbound_importtemplates(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/importtemplates', params=params, **kwargs)

    def post_outbound_importtemplates(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/importtemplates', params=params, body=body, **kwargs)

    def post_outbound_importtemplates_bulk_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/importtemplates/bulk/add', params=params, body=body, **kwargs)

    def delete_outbound_importtemplate(self, import_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/importtemplates/{quote(str(import_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_importtemplate(self, import_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/importtemplates/{quote(str(import_template_id), safe='')}", params=params, **kwargs)

    def put_outbound_importtemplate(self, import_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/importtemplates/{quote(str(import_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_importtemplate_importstatus(self, import_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/importtemplates/{quote(str(import_template_id), safe='')}/importstatus", params=params, **kwargs)

    def get_outbound_messagingcampaigns(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/messagingcampaigns', params=params, **kwargs)

    def post_outbound_messagingcampaigns(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/messagingcampaigns', params=params, body=body, **kwargs)

    def get_outbound_messagingcampaigns_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/messagingcampaigns/divisionviews', params=params, **kwargs)

    def get_outbound_messagingcampaigns_divisionview(self, messaging_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/messagingcampaigns/divisionviews/{quote(str(messaging_campaign_id), safe='')}", params=params, **kwargs)

    def post_outbound_messagingcampaigns_progress(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/messagingcampaigns/progress', params=params, body=body, **kwargs)

    def delete_outbound_messagingcampaign(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_messagingcampaign(self, messaging_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, **kwargs)

    def put_outbound_messagingcampaign(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_messagingcampaign_diagnostics(self, messaging_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}/diagnostics", params=params, **kwargs)

    def delete_outbound_messagingcampaign_progress(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}/progress", params=params, body=body, **kwargs)

    def get_outbound_messagingcampaign_progress(self, messaging_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}/progress", params=params, **kwargs)

    def post_outbound_messagingcampaign_start(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}/start", params=params, body=body, **kwargs)

    def post_outbound_messagingcampaign_stop(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/outbound/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}/stop", params=params, body=body, **kwargs)

    def get_outbound_rulesets(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/rulesets', params=params, **kwargs)

    def post_outbound_rulesets(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/rulesets', params=params, body=body, **kwargs)

    def delete_outbound_ruleset(self, rule_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/rulesets/{quote(str(rule_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_ruleset(self, rule_set_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/rulesets/{quote(str(rule_set_id), safe='')}", params=params, **kwargs)

    def put_outbound_ruleset(self, rule_set_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/rulesets/{quote(str(rule_set_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_campaigns(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/schedules/campaigns', params=params, **kwargs)

    def delete_outbound_schedules_campaign(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/schedules/campaigns/{quote(str(campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_campaign(self, campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/schedules/campaigns/{quote(str(campaign_id), safe='')}", params=params, **kwargs)

    def put_outbound_schedules_campaign(self, campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/schedules/campaigns/{quote(str(campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_emailcampaigns(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/schedules/emailcampaigns', params=params, **kwargs)

    def delete_outbound_schedules_emailcampaign(self, email_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/schedules/emailcampaigns/{quote(str(email_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_emailcampaign(self, email_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/schedules/emailcampaigns/{quote(str(email_campaign_id), safe='')}", params=params, **kwargs)

    def put_outbound_schedules_emailcampaign(self, email_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/schedules/emailcampaigns/{quote(str(email_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_messagingcampaigns(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/schedules/messagingcampaigns', params=params, **kwargs)

    def delete_outbound_schedules_messagingcampaign(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/schedules/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_messagingcampaign(self, messaging_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/schedules/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, **kwargs)

    def put_outbound_schedules_messagingcampaign(self, messaging_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/schedules/messagingcampaigns/{quote(str(messaging_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_sequences(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/schedules/sequences', params=params, **kwargs)

    def delete_outbound_schedules_sequence(self, sequence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/schedules/sequences/{quote(str(sequence_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_sequence(self, sequence_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/schedules/sequences/{quote(str(sequence_id), safe='')}", params=params, **kwargs)

    def put_outbound_schedules_sequence(self, sequence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/schedules/sequences/{quote(str(sequence_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_whatsappcampaigns(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/schedules/whatsappcampaigns', params=params, **kwargs)

    def delete_outbound_schedules_whatsappcampaign(self, whats_app_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/schedules/whatsappcampaigns/{quote(str(whats_app_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_schedules_whatsappcampaign(self, whats_app_campaign_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/schedules/whatsappcampaigns/{quote(str(whats_app_campaign_id), safe='')}", params=params, **kwargs)

    def put_outbound_schedules_whatsappcampaign(self, whats_app_campaign_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/schedules/whatsappcampaigns/{quote(str(whats_app_campaign_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_sequences(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/sequences', params=params, **kwargs)

    def post_outbound_sequences(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/outbound/sequences', params=params, body=body, **kwargs)

    def delete_outbound_sequence(self, sequence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/outbound/sequences/{quote(str(sequence_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_sequence(self, sequence_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/outbound/sequences/{quote(str(sequence_id), safe='')}", params=params, **kwargs)

    def put_outbound_sequence(self, sequence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/outbound/sequences/{quote(str(sequence_id), safe='')}", params=params, body=body, **kwargs)

    def get_outbound_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/settings', params=params, **kwargs)

    def patch_outbound_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/outbound/settings', params=params, body=body, **kwargs)

    def get_outbound_wrapupcodemappings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/outbound/wrapupcodemappings', params=params, **kwargs)

    def put_outbound_wrapupcodemappings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/outbound/wrapupcodemappings', params=params, body=body, **kwargs)

    def get_presence_definitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/presence/definitions', params=params, **kwargs)

    def post_presence_definitions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/presence/definitions', params=params, body=body, **kwargs)

    def delete_presence_definition(self, definition_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/presence/definitions/{quote(str(definition_id), safe='')}", params=params, body=body, **kwargs)

    def get_presence_definition(self, definition_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/presence/definitions/{quote(str(definition_id), safe='')}", params=params, **kwargs)

    def put_presence_definition(self, definition_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/presence/definitions/{quote(str(definition_id), safe='')}", params=params, body=body, **kwargs)

    def get_presence_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/presence/settings', params=params, **kwargs)

    def put_presence_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/presence/settings', params=params, body=body, **kwargs)

    def get_presence_sources(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/presence/sources', params=params, **kwargs)

    def post_presence_sources(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/presence/sources', params=params, body=body, **kwargs)

    def delete_presence_source(self, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/presence/sources/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_presence_source(self, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/presence/sources/{quote(str(source_id), safe='')}", params=params, **kwargs)

    def put_presence_source(self, source_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/presence/sources/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_presence_user_primarysource(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/presence/users/{quote(str(user_id), safe='')}/primarysource", params=params, **kwargs)

    def put_presence_user_primarysource(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/presence/users/{quote(str(user_id), safe='')}/primarysource", params=params, body=body, **kwargs)

    def get_presencedefinitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/presencedefinitions', params=params, **kwargs)

    def post_presencedefinitions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/presencedefinitions', params=params, body=body, **kwargs)

    def delete_presencedefinition(self, presence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/presencedefinitions/{quote(str(presence_id), safe='')}", params=params, body=body, **kwargs)

    def get_presencedefinition(self, presence_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/presencedefinitions/{quote(str(presence_id), safe='')}", params=params, **kwargs)

    def put_presencedefinition(self, presence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/presencedefinitions/{quote(str(presence_id), safe='')}", params=params, body=body, **kwargs)

    def get_processautomation_scheduledtriggers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/processautomation/scheduledtriggers', params=params, **kwargs)

    def post_processautomation_scheduledtriggers(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/processautomation/scheduledtriggers', params=params, body=body, **kwargs)

    def delete_processautomation_scheduledtrigger(self, scheduled_trigger_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/processautomation/scheduledtriggers/{quote(str(scheduled_trigger_id), safe='')}", params=params, body=body, **kwargs)

    def get_processautomation_scheduledtrigger(self, scheduled_trigger_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/processautomation/scheduledtriggers/{quote(str(scheduled_trigger_id), safe='')}", params=params, **kwargs)

    def put_processautomation_scheduledtrigger(self, scheduled_trigger_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/processautomation/scheduledtriggers/{quote(str(scheduled_trigger_id), safe='')}", params=params, body=body, **kwargs)

    def get_processautomation_triggers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/processautomation/triggers', params=params, **kwargs)

    def post_processautomation_triggers(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/processautomation/triggers', params=params, body=body, **kwargs)

    def get_processautomation_triggers_topics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/processautomation/triggers/topics', params=params, **kwargs)

    def post_processautomation_triggers_topic_test(self, topic_name, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/processautomation/triggers/topics/{quote(str(topic_name), safe='')}/test", params=params, body=body, **kwargs)

    def delete_processautomation_trigger(self, trigger_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/processautomation/triggers/{quote(str(trigger_id), safe='')}", params=params, body=body, **kwargs)

    def get_processautomation_trigger(self, trigger_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/processautomation/triggers/{quote(str(trigger_id), safe='')}", params=params, **kwargs)

    def put_processautomation_trigger(self, trigger_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/processautomation/triggers/{quote(str(trigger_id), safe='')}", params=params, body=body, **kwargs)

    def post_processautomation_trigger_test(self, trigger_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/processautomation/triggers/{quote(str(trigger_id), safe='')}/test", params=params, body=body, **kwargs)

    def get_profiles_groups(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/profiles/groups', params=params, **kwargs)

    def get_profiles_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/profiles/users', params=params, **kwargs)

    def get_quality_agents_activity(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/agents/activity', params=params, **kwargs)

    def get_quality_calibrations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/calibrations', params=params, **kwargs)

    def post_quality_calibrations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/calibrations', params=params, body=body, **kwargs)

    def delete_quality_calibration(self, calibration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/calibrations/{quote(str(calibration_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_calibration(self, calibration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/calibrations/{quote(str(calibration_id), safe='')}", params=params, **kwargs)

    def put_quality_calibration(self, calibration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/calibrations/{quote(str(calibration_id), safe='')}", params=params, body=body, **kwargs)

    def post_quality_conversations_audits_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/conversations/audits/query', params=params, body=body, **kwargs)

    def get_quality_conversations_audits_query_transaction_id(self, transaction_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/conversations/audits/query/{quote(str(transaction_id), safe='')}", params=params, **kwargs)

    def get_quality_conversations_audits_query_transaction_id_results(self, transaction_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/conversations/audits/query/{quote(str(transaction_id), safe='')}/results", params=params, **kwargs)

    def post_quality_conversation_evaluations(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/quality/conversations/{quote(str(conversation_id), safe='')}/evaluations", params=params, body=body, **kwargs)

    def delete_quality_conversation_evaluation(self, conversation_id, evaluation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/conversations/{quote(str(conversation_id), safe='')}/evaluations/{quote(str(evaluation_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_conversation_evaluation(self, conversation_id, evaluation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/conversations/{quote(str(conversation_id), safe='')}/evaluations/{quote(str(evaluation_id), safe='')}", params=params, **kwargs)

    def put_quality_conversation_evaluation(self, conversation_id, evaluation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/conversations/{quote(str(conversation_id), safe='')}/evaluations/{quote(str(evaluation_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_conversation_surveys(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/conversations/{quote(str(conversation_id), safe='')}/surveys", params=params, **kwargs)

    def post_quality_evaluations_aggregates_query_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/evaluations/aggregates/query/me', params=params, body=body, **kwargs)

    def get_quality_evaluations_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/evaluations/query', params=params, **kwargs)

    def post_quality_evaluations_scoring(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/evaluations/scoring', params=params, body=body, **kwargs)

    def post_quality_evaluations_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/evaluations/search', params=params, body=body, **kwargs)

    def get_quality_evaluators_activity(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/evaluators/activity', params=params, **kwargs)

    def get_quality_forms(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms', params=params, **kwargs)

    def post_quality_forms(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/forms', params=params, body=body, **kwargs)

    def post_quality_forms_evaluations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/forms/evaluations', params=params, body=body, **kwargs)

    def get_quality_forms_evaluations_bulk(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms/evaluations/bulk', params=params, **kwargs)

    def get_quality_forms_evaluations_bulk_contexts(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms/evaluations/bulk/contexts', params=params, **kwargs)

    def delete_quality_forms_evaluation(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/forms/evaluations/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_forms_evaluation(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/evaluations/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def put_quality_forms_evaluation(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/forms/evaluations/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def put_quality_forms_evaluation_aiscoring_settings(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/forms/evaluations/{quote(str(form_id), safe='')}/aiscoring/settings", params=params, body=body, **kwargs)

    def get_quality_forms_evaluation_versions(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/evaluations/{quote(str(form_id), safe='')}/versions", params=params, **kwargs)

    def get_quality_forms_surveys(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms/surveys', params=params, **kwargs)

    def post_quality_forms_surveys(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/forms/surveys', params=params, body=body, **kwargs)

    def get_quality_forms_surveys_bulk(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms/surveys/bulk', params=params, **kwargs)

    def get_quality_forms_surveys_bulk_contexts(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/forms/surveys/bulk/contexts', params=params, **kwargs)

    def delete_quality_forms_survey(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/forms/surveys/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_forms_survey(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/surveys/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def patch_quality_forms_survey(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/quality/forms/surveys/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def put_quality_forms_survey(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/forms/surveys/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_forms_survey_versions(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/surveys/{quote(str(form_id), safe='')}/versions", params=params, **kwargs)

    def delete_quality_form(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/forms/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_form(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def put_quality_form(self, form_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/forms/{quote(str(form_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_form_versions(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/forms/{quote(str(form_id), safe='')}/versions", params=params, **kwargs)

    def get_quality_program_agentscoringrules(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/programs/{quote(str(program_id), safe='')}/agentscoringrules", params=params, **kwargs)

    def post_quality_program_agentscoringrules(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/quality/programs/{quote(str(program_id), safe='')}/agentscoringrules", params=params, body=body, **kwargs)

    def delete_quality_program_agentscoringrule(self, program_id, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/quality/programs/{quote(str(program_id), safe='')}/agentscoringrules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_program_agentscoringrule(self, program_id, rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/programs/{quote(str(program_id), safe='')}/agentscoringrules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def put_quality_program_agentscoringrule(self, program_id, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/quality/programs/{quote(str(program_id), safe='')}/agentscoringrules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_quality_publishedforms(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/publishedforms', params=params, **kwargs)

    def post_quality_publishedforms(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/publishedforms', params=params, body=body, **kwargs)

    def get_quality_publishedforms_evaluations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/publishedforms/evaluations', params=params, **kwargs)

    def post_quality_publishedforms_evaluations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/publishedforms/evaluations', params=params, body=body, **kwargs)

    def get_quality_publishedforms_evaluations_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/publishedforms/evaluations/divisionviews', params=params, **kwargs)

    def get_quality_publishedforms_evaluations_divisionview(self, evaluation_form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/publishedforms/evaluations/divisionviews/{quote(str(evaluation_form_id), safe='')}", params=params, **kwargs)

    def get_quality_publishedforms_evaluation(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/publishedforms/evaluations/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def get_quality_publishedforms_surveys(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/publishedforms/surveys', params=params, **kwargs)

    def post_quality_publishedforms_surveys(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/publishedforms/surveys', params=params, body=body, **kwargs)

    def get_quality_publishedforms_surveys_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/publishedforms/surveys/divisionviews', params=params, **kwargs)

    def get_quality_publishedforms_surveys_divisionview(self, survey_form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/publishedforms/surveys/divisionviews/{quote(str(survey_form_id), safe='')}", params=params, **kwargs)

    def get_quality_publishedforms_survey(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/publishedforms/surveys/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def get_quality_publishedform(self, form_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/publishedforms/{quote(str(form_id), safe='')}", params=params, **kwargs)

    def post_quality_surveys(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/surveys', params=params, body=body, **kwargs)

    def get_quality_surveys_scorable(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/quality/surveys/scorable', params=params, **kwargs)

    def put_quality_surveys_scorable(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/quality/surveys/scorable', params=params, body=body, **kwargs)

    def post_quality_surveys_scoring(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/quality/surveys/scoring', params=params, body=body, **kwargs)

    def get_quality_survey(self, survey_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/quality/surveys/{quote(str(survey_id), safe='')}", params=params, **kwargs)

    def post_recording_batchrequests(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/batchrequests', params=params, body=body, **kwargs)

    def get_recording_batchrequest(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/batchrequests/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def delete_recording_crossplatform_mediaretentionpolicies(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/recording/crossplatform/mediaretentionpolicies', params=params, body=body, **kwargs)

    def get_recording_crossplatform_mediaretentionpolicies(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/crossplatform/mediaretentionpolicies', params=params, **kwargs)

    def post_recording_crossplatform_mediaretentionpolicies(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/crossplatform/mediaretentionpolicies', params=params, body=body, **kwargs)

    def delete_recording_crossplatform_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/recording/crossplatform/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_crossplatform_mediaretentionpolicy(self, policy_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/crossplatform/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, **kwargs)

    def patch_recording_crossplatform_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/recording/crossplatform/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def put_recording_crossplatform_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/recording/crossplatform/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/jobs', params=params, **kwargs)

    def post_recording_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/jobs', params=params, body=body, **kwargs)

    def delete_recording_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/recording/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def put_recording_job(self, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/recording/jobs/{quote(str(job_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_job_failedrecordings(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/jobs/{quote(str(job_id), safe='')}/failedrecordings", params=params, **kwargs)

    def get_recording_keyconfigurations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/keyconfigurations', params=params, **kwargs)

    def post_recording_keyconfigurations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/keyconfigurations', params=params, body=body, **kwargs)

    def post_recording_keyconfigurations_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/keyconfigurations/validate', params=params, body=body, **kwargs)

    def get_recording_keyconfiguration(self, key_configuration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/keyconfigurations/{quote(str(key_configuration_id), safe='')}", params=params, **kwargs)

    def put_recording_keyconfiguration(self, key_configuration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/recording/keyconfigurations/{quote(str(key_configuration_id), safe='')}", params=params, body=body, **kwargs)

    def post_recording_localkeys(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/localkeys', params=params, body=body, **kwargs)

    def delete_recording_mediaretentionpolicies(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/recording/mediaretentionpolicies', params=params, body=body, **kwargs)

    def post_recording_mediaretentionpolicies(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/mediaretentionpolicies', params=params, body=body, **kwargs)

    def delete_recording_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/recording/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_mediaretentionpolicy(self, policy_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, **kwargs)

    def patch_recording_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/recording/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def put_recording_mediaretentionpolicy(self, policy_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/recording/mediaretentionpolicies/{quote(str(policy_id), safe='')}", params=params, body=body, **kwargs)

    def get_recording_recordingkeys(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/recordingkeys', params=params, **kwargs)

    def post_recording_recordingkeys(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/recordingkeys', params=params, body=body, **kwargs)

    def get_recording_recordingkeys_rotationschedule(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/recordingkeys/rotationschedule', params=params, **kwargs)

    def put_recording_recordingkeys_rotationschedule(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/recording/recordingkeys/rotationschedule', params=params, body=body, **kwargs)

    def get_recording_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recording/settings', params=params, **kwargs)

    def put_recording_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/recording/settings', params=params, body=body, **kwargs)

    def post_recording_uploads_reports(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recording/uploads/reports', params=params, body=body, **kwargs)

    def get_recording_uploads_report(self, report_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/recording/uploads/reports/{quote(str(report_id), safe='')}", params=params, **kwargs)

    def post_recordings_deletionprotection(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recordings/deletionprotection', params=params, body=body, **kwargs)

    def put_recordings_deletionprotection(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/recordings/deletionprotection', params=params, body=body, **kwargs)

    def get_recordings_retention_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recordings/retention/query', params=params, **kwargs)

    def post_recordings_screensessions_acknowledge(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recordings/screensessions/acknowledge', params=params, body=body, **kwargs)

    def get_recordings_screensessions_details(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/recordings/screensessions/details', params=params, **kwargs)

    def post_recordings_screensessions_metadata(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/recordings/screensessions/metadata', params=params, body=body, **kwargs)

    def get_responsemanagement_libraries(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/responsemanagement/libraries', params=params, **kwargs)

    def post_responsemanagement_libraries(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/libraries', params=params, body=body, **kwargs)

    def post_responsemanagement_libraries_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/libraries/bulk', params=params, body=body, **kwargs)

    def get_responsemanagement_libraries_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/responsemanagement/libraries/divisionviews', params=params, **kwargs)

    def get_responsemanagement_libraries_divisionview(self, library_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/libraries/divisionviews/{quote(str(library_id), safe='')}", params=params, **kwargs)

    def post_responsemanagement_libraries_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/libraries/query', params=params, body=body, **kwargs)

    def delete_responsemanagement_library(self, library_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/responsemanagement/libraries/{quote(str(library_id), safe='')}", params=params, body=body, **kwargs)

    def get_responsemanagement_library(self, library_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/libraries/{quote(str(library_id), safe='')}", params=params, **kwargs)

    def put_responsemanagement_library(self, library_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/responsemanagement/libraries/{quote(str(library_id), safe='')}", params=params, body=body, **kwargs)

    def post_responsemanagement_responseassets_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responseassets/bulk', params=params, body=body, **kwargs)

    def post_responsemanagement_responseassets_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responseassets/search', params=params, body=body, **kwargs)

    def get_responsemanagement_responseassets_status_status_id(self, status_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/responseassets/status/{quote(str(status_id), safe='')}", params=params, **kwargs)

    def post_responsemanagement_responseassets_uploads(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responseassets/uploads', params=params, body=body, **kwargs)

    def delete_responsemanagement_responseasset(self, response_asset_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/responsemanagement/responseassets/{quote(str(response_asset_id), safe='')}", params=params, body=body, **kwargs)

    def get_responsemanagement_responseasset(self, response_asset_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/responseassets/{quote(str(response_asset_id), safe='')}", params=params, **kwargs)

    def put_responsemanagement_responseasset(self, response_asset_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/responsemanagement/responseassets/{quote(str(response_asset_id), safe='')}", params=params, body=body, **kwargs)

    def get_responsemanagement_responses(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/responsemanagement/responses', params=params, **kwargs)

    def post_responsemanagement_responses(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responses', params=params, body=body, **kwargs)

    def post_responsemanagement_responses_divisionviews_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responses/divisionviews/query', params=params, body=body, **kwargs)

    def get_responsemanagement_responses_divisionview(self, response_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/responses/divisionviews/{quote(str(response_id), safe='')}", params=params, **kwargs)

    def post_responsemanagement_responses_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/responsemanagement/responses/query', params=params, body=body, **kwargs)

    def delete_responsemanagement_response(self, response_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/responsemanagement/responses/{quote(str(response_id), safe='')}", params=params, body=body, **kwargs)

    def get_responsemanagement_response(self, response_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/responsemanagement/responses/{quote(str(response_id), safe='')}", params=params, **kwargs)

    def put_responsemanagement_response(self, response_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/responsemanagement/responses/{quote(str(response_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_assessments(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/assessments', params=params, **kwargs)

    def post_routing_assessments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/assessments', params=params, body=body, **kwargs)

    def get_routing_assessments_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/assessments/jobs', params=params, **kwargs)

    def post_routing_assessments_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/assessments/jobs', params=params, body=body, **kwargs)

    def get_routing_assessments_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/assessments/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def delete_routing_assessment(self, assessment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/assessments/{quote(str(assessment_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_assessment(self, assessment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/assessments/{quote(str(assessment_id), safe='')}", params=params, **kwargs)

    def get_routing_availablemediatypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/availablemediatypes', params=params, **kwargs)

    def patch_routing_conversation(self, conversation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/conversations/{quote(str(conversation_id), safe='')}", params=params, body=body, **kwargs)

    def delete_routing_directroutingbackup_settings_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/routing/directroutingbackup/settings/me', params=params, body=body, **kwargs)

    def get_routing_directroutingbackup_settings_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/directroutingbackup/settings/me', params=params, **kwargs)

    def put_routing_directroutingbackup_settings_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/routing/directroutingbackup/settings/me', params=params, body=body, **kwargs)

    def post_routing_email_domains(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/email/domains', params=params, body=body, **kwargs)

    def delete_routing_email_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_domain(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}", params=params, **kwargs)

    def patch_routing_email_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_domain_dkim(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/dkim", params=params, **kwargs)

    def post_routing_email_domain_dkim(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/dkim", params=params, body=body, **kwargs)

    def get_routing_email_domain_mailfrom(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/mailfrom", params=params, **kwargs)

    def post_routing_email_domain_mailfrom(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/mailfrom", params=params, body=body, **kwargs)

    def post_routing_email_domain_testconnection(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/testconnection", params=params, body=body, **kwargs)

    def patch_routing_email_domain_validate(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/validate", params=params, body=body, **kwargs)

    def get_routing_email_domain_verification(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/verification", params=params, **kwargs)

    def post_routing_email_domain_verification(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/domains/{quote(str(domain_id), safe='')}/verification", params=params, body=body, **kwargs)

    def get_routing_email_domain_routes(self, domain_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes", params=params, **kwargs)

    def post_routing_email_domain_routes(self, domain_name, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes", params=params, body=body, **kwargs)

    def delete_routing_email_domain_route(self, domain_name, route_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes/{quote(str(route_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_domain_route(self, domain_name, route_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes/{quote(str(route_id), safe='')}", params=params, **kwargs)

    def put_routing_email_domain_route(self, domain_name, route_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes/{quote(str(route_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_domain_route_identityresolution(self, domain_name, route_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes/{quote(str(route_id), safe='')}/identityresolution", params=params, **kwargs)

    def put_routing_email_domain_route_identityresolution(self, domain_name, route_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/email/domains/{quote(str(domain_name), safe='')}/routes/{quote(str(route_id), safe='')}/identityresolution", params=params, body=body, **kwargs)

    def get_routing_email_outbound_domains(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/email/outbound/domains', params=params, **kwargs)

    def post_routing_email_outbound_domains(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/email/outbound/domains', params=params, body=body, **kwargs)

    def post_routing_email_outbound_domains_simulated(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/email/outbound/domains/simulated', params=params, body=body, **kwargs)

    def delete_routing_email_outbound_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_outbound_domain(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}", params=params, **kwargs)

    def patch_routing_email_outbound_domain(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_outbound_domain_activation(self, domain_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}/activation", params=params, **kwargs)

    def put_routing_email_outbound_domain_activation(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}/activation", params=params, body=body, **kwargs)

    def post_routing_email_outbound_domain_testconnection(self, domain_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/email/outbound/domains/{quote(str(domain_id), safe='')}/testconnection", params=params, body=body, **kwargs)

    def get_routing_email_setting(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/email/setting', params=params, **kwargs)

    def post_routing_email_setting(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/email/setting', params=params, body=body, **kwargs)

    def delete_routing_email_setting_email_setting_id(self, email_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/email/setting/{quote(str(email_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_setting_email_setting_id(self, email_setting_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/email/setting/{quote(str(email_setting_id), safe='')}", params=params, **kwargs)

    def patch_routing_email_setting_email_setting_id(self, email_setting_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/email/setting/{quote(str(email_setting_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_email_setup(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/email/setup', params=params, **kwargs)

    def post_routing_languages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/languages', params=params, body=body, **kwargs)

    def delete_routing_language(self, language_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/languages/{quote(str(language_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_language(self, language_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/languages/{quote(str(language_id), safe='')}", params=params, **kwargs)

    def get_routing_message_recipient(self, recipient_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/message/recipients/{quote(str(recipient_id), safe='')}", params=params, **kwargs)

    def put_routing_message_recipient(self, recipient_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/message/recipients/{quote(str(recipient_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_predictors(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/predictors', params=params, **kwargs)

    def post_routing_predictors(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/predictors', params=params, body=body, **kwargs)

    def get_routing_predictors_keyperformanceindicators(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/predictors/keyperformanceindicators', params=params, **kwargs)

    def post_routing_predictors_keyperformanceindicators(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/predictors/keyperformanceindicators', params=params, body=body, **kwargs)

    def delete_routing_predictors_keyperformanceindicator(self, kpi_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/predictors/keyperformanceindicators/{quote(str(kpi_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_predictors_keyperformanceindicator(self, kpi_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/predictors/keyperformanceindicators/{quote(str(kpi_id), safe='')}", params=params, **kwargs)

    def patch_routing_predictors_keyperformanceindicator(self, kpi_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/predictors/keyperformanceindicators/{quote(str(kpi_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_predictors_keyperformanceindicatortypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/predictors/keyperformanceindicatortypes', params=params, **kwargs)

    def delete_routing_predictor(self, predictor_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/predictors/{quote(str(predictor_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_predictor(self, predictor_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/predictors/{quote(str(predictor_id), safe='')}", params=params, **kwargs)

    def patch_routing_predictor(self, predictor_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/predictors/{quote(str(predictor_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_predictor_models(self, predictor_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/predictors/{quote(str(predictor_id), safe='')}/models", params=params, **kwargs)

    def get_routing_predictor_model_features(self, model_id, predictor_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/predictors/{quote(str(predictor_id), safe='')}/models/{quote(str(model_id), safe='')}/features", params=params, **kwargs)

    def post_routing_queues(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/queues', params=params, body=body, **kwargs)

    def get_routing_queues_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/queues/divisionviews', params=params, **kwargs)

    def get_routing_queues_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/queues/me', params=params, **kwargs)

    def delete_routing_queue(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_queue_assistant(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/assistant", params=params, **kwargs)

    def get_routing_queue_comparisonperiods(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/comparisonperiods", params=params, **kwargs)

    def get_routing_queue_comparisonperiod(self, comparison_period_id, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/comparisonperiods/{quote(str(comparison_period_id), safe='')}", params=params, **kwargs)

    def get_routing_queue_estimatedwaittime(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/estimatedwaittime", params=params, **kwargs)

    def get_routing_queue_identityresolution(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/identityresolution", params=params, **kwargs)

    def put_routing_queue_identityresolution(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/identityresolution", params=params, body=body, **kwargs)

    def get_routing_queue_mediatype_estimatedwaittime(self, media_type, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/mediatypes/{quote(str(media_type), safe='')}/estimatedwaittime", params=params, **kwargs)

    def patch_routing_queue_members(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/members", params=params, body=body, **kwargs)

    def post_routing_queue_members(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/members", params=params, body=body, **kwargs)

    def delete_routing_queue_member(self, member_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/members/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def patch_routing_queue_member(self, member_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/members/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_queue_users(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/users", params=params, **kwargs)

    def patch_routing_queue_users(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/users", params=params, body=body, **kwargs)

    def post_routing_queue_users(self, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/users", params=params, body=body, **kwargs)

    def delete_routing_queue_user(self, member_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/users/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def patch_routing_queue_user(self, member_id, queue_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/queues/{quote(str(queue_id), safe='')}/users/{quote(str(member_id), safe='')}", params=params, body=body, **kwargs)

    def delete_routing_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/routing/settings', params=params, body=body, **kwargs)

    def put_routing_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/routing/settings', params=params, body=body, **kwargs)

    def get_routing_settings_contactcenter(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/settings/contactcenter', params=params, **kwargs)

    def patch_routing_settings_contactcenter(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/routing/settings/contactcenter', params=params, body=body, **kwargs)

    def get_routing_settings_transcription(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/settings/transcription', params=params, **kwargs)

    def patch_routing_settings_transcription(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/routing/settings/transcription', params=params, body=body, **kwargs)

    def put_routing_settings_transcription(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/routing/settings/transcription', params=params, body=body, **kwargs)

    def delete_routing_skillexpressions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/routing/skillexpressions', params=params, body=body, **kwargs)

    def get_routing_skillexpressions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/skillexpressions', params=params, **kwargs)

    def get_routing_skillexpressions_queue_queue_id(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skillexpressions/queue/{quote(str(queue_id), safe='')}", params=params, **kwargs)

    def post_routing_skillexpressions_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/skillexpressions/validate', params=params, body=body, **kwargs)

    def delete_routing_skillexpression(self, expression_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/skillexpressions/{quote(str(expression_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_skillexpression(self, expression_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skillexpressions/{quote(str(expression_id), safe='')}", params=params, **kwargs)

    def post_routing_skillgroups(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/skillgroups', params=params, body=body, **kwargs)

    def delete_routing_skillgroup(self, skill_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_skillgroup(self, skill_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}", params=params, **kwargs)

    def patch_routing_skillgroup(self, skill_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_skillgroup_members(self, skill_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}/members", params=params, **kwargs)

    def get_routing_skillgroup_members_divisions(self, skill_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}/members/divisions", params=params, **kwargs)

    def post_routing_skillgroup_members_divisions(self, skill_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/routing/skillgroups/{quote(str(skill_group_id), safe='')}/members/divisions", params=params, body=body, **kwargs)

    def post_routing_skills(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/skills', params=params, body=body, **kwargs)

    def delete_routing_skill(self, skill_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/skills/{quote(str(skill_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_skill(self, skill_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/skills/{quote(str(skill_id), safe='')}", params=params, **kwargs)

    def patch_routing_skill(self, skill_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/skills/{quote(str(skill_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_sms_addresses(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/sms/addresses', params=params, **kwargs)

    def post_routing_sms_addresses(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/sms/addresses', params=params, body=body, **kwargs)

    def delete_routing_sms_address(self, address_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/sms/addresses/{quote(str(address_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_sms_address(self, address_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/sms/addresses/{quote(str(address_id), safe='')}", params=params, **kwargs)

    def get_routing_sms_availablephonenumbers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/sms/availablephonenumbers', params=params, **kwargs)

    def get_routing_sms_identityresolution_phonenumber(self, address_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/sms/identityresolution/phonenumbers/{quote(str(address_id), safe='')}", params=params, **kwargs)

    def put_routing_sms_identityresolution_phonenumber(self, address_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/sms/identityresolution/phonenumbers/{quote(str(address_id), safe='')}", params=params, body=body, **kwargs)

    def post_routing_sms_phonenumbers(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/sms/phonenumbers', params=params, body=body, **kwargs)

    def post_routing_sms_phonenumbers_import(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/sms/phonenumbers/import', params=params, body=body, **kwargs)

    def delete_routing_sms_phonenumber(self, phone_number_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/sms/phonenumbers/{quote(str(phone_number_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_sms_phonenumber(self, phone_number_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/sms/phonenumbers/{quote(str(phone_number_id), safe='')}", params=params, **kwargs)

    def patch_routing_sms_phonenumber(self, phone_number_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/routing/sms/phonenumbers/{quote(str(phone_number_id), safe='')}", params=params, body=body, **kwargs)

    def delete_routing_user_directroutingbackup_settings(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/directroutingbackup/settings", params=params, body=body, **kwargs)

    def get_routing_user_directroutingbackup_settings(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/directroutingbackup/settings", params=params, **kwargs)

    def put_routing_user_directroutingbackup_settings(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/directroutingbackup/settings", params=params, body=body, **kwargs)

    def delete_routing_user_utilization(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/utilization", params=params, body=body, **kwargs)

    def get_routing_user_utilization(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/utilization", params=params, **kwargs)

    def put_routing_user_utilization(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/users/{quote(str(user_id), safe='')}/utilization", params=params, body=body, **kwargs)

    def delete_routing_utilization(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/routing/utilization', params=params, body=body, **kwargs)

    def get_routing_utilization(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/utilization', params=params, **kwargs)

    def put_routing_utilization(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/routing/utilization', params=params, body=body, **kwargs)

    def get_routing_utilization_labels(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/utilization/labels', params=params, **kwargs)

    def post_routing_utilization_labels(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/routing/utilization/labels', params=params, body=body, **kwargs)

    def delete_routing_utilization_label(self, label_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/utilization/labels/{quote(str(label_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_utilization_label(self, label_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/utilization/labels/{quote(str(label_id), safe='')}", params=params, **kwargs)

    def put_routing_utilization_label(self, label_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/routing/utilization/labels/{quote(str(label_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_utilization_label_agents(self, label_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/utilization/labels/{quote(str(label_id), safe='')}/agents", params=params, **kwargs)

    def get_routing_wrapupcodes_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/routing/wrapupcodes/divisionviews', params=params, **kwargs)

    def get_routing_wrapupcodes_divisionview(self, code_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/wrapupcodes/divisionviews/{quote(str(code_id), safe='')}", params=params, **kwargs)

    def delete_routing_wrapupcode(self, code_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/routing/wrapupcodes/{quote(str(code_id), safe='')}", params=params, body=body, **kwargs)

    def get_routing_wrapupcode(self, code_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/routing/wrapupcodes/{quote(str(code_id), safe='')}", params=params, **kwargs)

    def get_scim_groups(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/groups', params=params, **kwargs)

    def get_scim_group(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/groups/{quote(str(group_id), safe='')}", params=params, **kwargs)

    def patch_scim_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/scim/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def put_scim_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/scim/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def get_scim_resourcetypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/resourcetypes', params=params, **kwargs)

    def get_scim_resourcetype(self, resource_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/resourcetypes/{quote(str(resource_type), safe='')}", params=params, **kwargs)

    def get_scim_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/schemas', params=params, **kwargs)

    def get_scim_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def get_scim_serviceproviderconfig(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/serviceproviderconfig', params=params, **kwargs)

    def get_scim_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/users', params=params, **kwargs)

    def post_scim_users(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/scim/users', params=params, body=body, **kwargs)

    def delete_scim_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/scim/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_scim_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def patch_scim_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/scim/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def put_scim_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/scim/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_scim_v2_groups(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/v2/groups', params=params, **kwargs)

    def get_scim_v2_group(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/v2/groups/{quote(str(group_id), safe='')}", params=params, **kwargs)

    def patch_scim_v2_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/scim/v2/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def put_scim_v2_group(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/scim/v2/groups/{quote(str(group_id), safe='')}", params=params, body=body, **kwargs)

    def get_scim_v2_resourcetypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/v2/resourcetypes', params=params, **kwargs)

    def get_scim_v2_resourcetype(self, resource_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/v2/resourcetypes/{quote(str(resource_type), safe='')}", params=params, **kwargs)

    def get_scim_v2_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/v2/schemas', params=params, **kwargs)

    def get_scim_v2_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/v2/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def get_scim_v2_serviceproviderconfig(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/v2/serviceproviderconfig', params=params, **kwargs)

    def get_scim_v2_users(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scim/v2/users', params=params, **kwargs)

    def post_scim_v2_users(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/scim/v2/users', params=params, body=body, **kwargs)

    def delete_scim_v2_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/scim/v2/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_scim_v2_user(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scim/v2/users/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def patch_scim_v2_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/scim/v2/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def put_scim_v2_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/scim/v2/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_screenmonitors_sessions_details(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/screenmonitors/sessions/details', params=params, **kwargs)

    def post_screenmonitors_sessions_users_details(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/screenmonitors/sessions/users/details', params=params, body=body, **kwargs)

    def get_screenmonitors_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/screenmonitors/settings', params=params, **kwargs)

    def put_screenmonitors_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/screenmonitors/settings', params=params, body=body, **kwargs)

    def get_screenmonitors_user_sessions(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/screenmonitors/users/{quote(str(user_id), safe='')}/sessions", params=params, **kwargs)

    def post_screenrecording_token(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/screenrecording/token', params=params, body=body, **kwargs)

    def get_scripts_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scripts/divisionviews', params=params, **kwargs)

    def get_scripts_published(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scripts/published', params=params, **kwargs)

    def post_scripts_published(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/scripts/published', params=params, body=body, **kwargs)

    def get_scripts_published_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/scripts/published/divisionviews', params=params, **kwargs)

    def get_scripts_published_divisionview_variables(self, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/published/divisionviews/{quote(str(script_id), safe='')}/variables", params=params, **kwargs)

    def get_scripts_published_script_id(self, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/published/{quote(str(script_id), safe='')}", params=params, **kwargs)

    def get_scripts_published_script_id_pages(self, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/published/{quote(str(script_id), safe='')}/pages", params=params, **kwargs)

    def get_scripts_published_script_id_page(self, page_id, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/published/{quote(str(script_id), safe='')}/pages/{quote(str(page_id), safe='')}", params=params, **kwargs)

    def get_scripts_published_script_id_variables(self, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/published/{quote(str(script_id), safe='')}/variables", params=params, **kwargs)

    def get_scripts_upload_status(self, upload_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/uploads/{quote(str(upload_id), safe='')}/status", params=params, **kwargs)

    def post_script_export(self, script_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/scripts/{quote(str(script_id), safe='')}/export", params=params, body=body, **kwargs)

    def get_script_pages(self, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/{quote(str(script_id), safe='')}/pages", params=params, **kwargs)

    def get_script_page(self, page_id, script_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/scripts/{quote(str(script_id), safe='')}/pages/{quote(str(page_id), safe='')}", params=params, **kwargs)

    def get_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/search', params=params, **kwargs)

    def post_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/search', params=params, body=body, **kwargs)

    def get_search_suggest(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/search/suggest', params=params, **kwargs)

    def post_search_suggest(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/search/suggest', params=params, body=body, **kwargs)

    def get_settings_executiondata(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/settings/executiondata', params=params, **kwargs)

    def patch_settings_executiondata(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/settings/executiondata', params=params, body=body, **kwargs)

    def post_socialmedia_analytics_aggregates_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/analytics/aggregates/jobs', params=params, body=body, **kwargs)

    def get_socialmedia_analytics_aggregates_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/analytics/aggregates/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_socialmedia_analytics_aggregates_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/analytics/aggregates/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def post_socialmedia_analytics_messages_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/analytics/messages/jobs', params=params, body=body, **kwargs)

    def get_socialmedia_analytics_messages_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/analytics/messages/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_socialmedia_analytics_messages_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/analytics/messages/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def get_socialmedia_escalationrules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/socialmedia/escalationrules', params=params, **kwargs)

    def post_socialmedia_escalationrules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/escalationrules', params=params, body=body, **kwargs)

    def delete_socialmedia_escalationrule(self, escalation_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/escalationrules/{quote(str(escalation_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_escalationrule(self, escalation_rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/escalationrules/{quote(str(escalation_rule_id), safe='')}", params=params, **kwargs)

    def put_socialmedia_escalationrule(self, escalation_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/socialmedia/escalationrules/{quote(str(escalation_rule_id), safe='')}", params=params, body=body, **kwargs)

    def post_socialmedia_escalations_messages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/escalations/messages', params=params, body=body, **kwargs)

    def get_socialmedia_topics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/socialmedia/topics', params=params, **kwargs)

    def post_socialmedia_topics(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/topics', params=params, body=body, **kwargs)

    def delete_socialmedia_topic(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic(self, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}", params=params, **kwargs)

    def patch_socialmedia_topic(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules(self, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules", params=params, **kwargs)

    def post_socialmedia_topic_dataingestionrules_facebook(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook", params=params, body=body, **kwargs)

    def delete_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id(self, facebook_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id(self, facebook_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}", params=params, **kwargs)

    def patch_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id(self, facebook_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def put_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id(self, facebook_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id_versions(self, facebook_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}/versions", params=params, **kwargs)

    def get_socialmedia_topic_dataingestionrules_facebook_facebook_ingestion_rule_id_version(self, data_ingestion_rule_version, facebook_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/facebook/{quote(str(facebook_ingestion_rule_id), safe='')}/versions/{quote(str(data_ingestion_rule_version), safe='')}", params=params, **kwargs)

    def post_socialmedia_topic_dataingestionrules_instagram(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram", params=params, body=body, **kwargs)

    def delete_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id(self, instagram_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id(self, instagram_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}", params=params, **kwargs)

    def patch_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id(self, instagram_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def put_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id(self, instagram_ingestion_rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id_versions(self, instagram_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}/versions", params=params, **kwargs)

    def get_socialmedia_topic_dataingestionrules_instagram_instagram_ingestion_rule_id_version(self, data_ingestion_rule_version, instagram_ingestion_rule_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/instagram/{quote(str(instagram_ingestion_rule_id), safe='')}/versions/{quote(str(data_ingestion_rule_version), safe='')}", params=params, **kwargs)

    def post_socialmedia_topic_dataingestionrules_open(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open", params=params, body=body, **kwargs)

    def delete_socialmedia_topic_dataingestionrules_open_open_id(self, open_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_open_open_id(self, open_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}", params=params, **kwargs)

    def patch_socialmedia_topic_dataingestionrules_open_open_id(self, open_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}", params=params, body=body, **kwargs)

    def put_socialmedia_topic_dataingestionrules_open_open_id(self, open_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_open_open_id_versions(self, open_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}/versions", params=params, **kwargs)

    def get_socialmedia_topic_dataingestionrules_open_open_id_version(self, data_ingestion_rule_version, open_id, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(open_id), safe='')}/versions/{quote(str(data_ingestion_rule_version), safe='')}", params=params, **kwargs)

    def post_socialmedia_topic_dataingestionrules_open_rule_id_messages_bulk(self, rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(rule_id), safe='')}/messages/bulk", params=params, body=body, **kwargs)

    def post_socialmedia_topic_dataingestionrules_open_rule_id_reactions_bulk(self, rule_id, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/open/{quote(str(rule_id), safe='')}/reactions/bulk", params=params, body=body, **kwargs)

    def post_socialmedia_topic_dataingestionrules_twitter(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter", params=params, body=body, **kwargs)

    def delete_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id(self, topic_id, twitter_ingestion_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id(self, topic_id, twitter_ingestion_rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}", params=params, **kwargs)

    def patch_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id(self, topic_id, twitter_ingestion_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def put_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id(self, topic_id, twitter_ingestion_rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id_versions(self, topic_id, twitter_ingestion_rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}/versions", params=params, **kwargs)

    def get_socialmedia_topic_dataingestionrules_twitter_twitter_ingestion_rule_id_version(self, data_ingestion_rule_version, topic_id, twitter_ingestion_rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/socialmedia/topics/{quote(str(topic_id), safe='')}/dataingestionrules/twitter/{quote(str(twitter_ingestion_rule_id), safe='')}/versions/{quote(str(data_ingestion_rule_version), safe='')}", params=params, **kwargs)

    def post_socialmedia_twitter_historical_tweets(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/socialmedia/twitter/historical/tweets', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_categories(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/categories', params=params, **kwargs)

    def post_speechandtextanalytics_categories(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/categories', params=params, body=body, **kwargs)

    def delete_speechandtextanalytics_category(self, category_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/speechandtextanalytics/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_category(self, category_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/categories/{quote(str(category_id), safe='')}", params=params, **kwargs)

    def put_speechandtextanalytics_category(self, category_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/categories/{quote(str(category_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_conversation(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/conversations/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def get_speechandtextanalytics_conversation_categories(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/conversations/{quote(str(conversation_id), safe='')}/categories", params=params, **kwargs)

    def get_speechandtextanalytics_conversation_communication_transcripturl(self, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/transcripturl", params=params, **kwargs)

    def get_speechandtextanalytics_conversation_communication_transcripturls(self, communication_id, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/conversations/{quote(str(conversation_id), safe='')}/communications/{quote(str(communication_id), safe='')}/transcripturls", params=params, **kwargs)

    def get_speechandtextanalytics_conversation_sentiments(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/conversations/{quote(str(conversation_id), safe='')}/sentiments", params=params, **kwargs)

    def get_speechandtextanalytics_dictionaryfeedback(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/dictionaryfeedback', params=params, **kwargs)

    def post_speechandtextanalytics_dictionaryfeedback(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/dictionaryfeedback', params=params, body=body, **kwargs)

    def delete_speechandtextanalytics_dictionaryfeedback_dictionary_feedback_id(self, dictionary_feedback_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/speechandtextanalytics/dictionaryfeedback/{quote(str(dictionary_feedback_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_dictionaryfeedback_dictionary_feedback_id(self, dictionary_feedback_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/dictionaryfeedback/{quote(str(dictionary_feedback_id), safe='')}", params=params, **kwargs)

    def put_speechandtextanalytics_dictionaryfeedback_dictionary_feedback_id(self, dictionary_feedback_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/dictionaryfeedback/{quote(str(dictionary_feedback_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_programs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs', params=params, **kwargs)

    def post_speechandtextanalytics_programs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/programs', params=params, body=body, **kwargs)

    def post_speechandtextanalytics_programs_general_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/programs/general/jobs', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_programs_general_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/general/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_speechandtextanalytics_programs_mappings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs/mappings', params=params, **kwargs)

    def post_speechandtextanalytics_programs_publishjobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/programs/publishjobs', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_programs_publishjob(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/publishjobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_speechandtextanalytics_programs_settings_insights(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs/settings/insights', params=params, **kwargs)

    def get_speechandtextanalytics_programs_settings_processing(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs/settings/processing', params=params, **kwargs)

    def get_speechandtextanalytics_programs_topiclinks_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/topiclinks/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_speechandtextanalytics_programs_transcriptionengines_dialects(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs/transcriptionengines/dialects', params=params, **kwargs)

    def get_speechandtextanalytics_programs_unpublished(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/programs/unpublished', params=params, **kwargs)

    def delete_speechandtextanalytics_program(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_program(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}", params=params, **kwargs)

    def put_speechandtextanalytics_program(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_program_mappings(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/mappings", params=params, **kwargs)

    def put_speechandtextanalytics_program_mappings(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/mappings", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_program_settings_insights(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/settings/insights", params=params, **kwargs)

    def put_speechandtextanalytics_program_settings_insights(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/settings/insights", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_program_settings_processing(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/settings/processing", params=params, **kwargs)

    def patch_speechandtextanalytics_program_settings_processing(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/settings/processing", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_program_transcriptionengines(self, program_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/transcriptionengines", params=params, **kwargs)

    def put_speechandtextanalytics_program_transcriptionengines(self, program_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/programs/{quote(str(program_id), safe='')}/transcriptionengines", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_sentiment_dialects(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/sentiment/dialects', params=params, **kwargs)

    def delete_speechandtextanalytics_sentimentfeedback(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/speechandtextanalytics/sentimentfeedback', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_sentimentfeedback(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/sentimentfeedback', params=params, **kwargs)

    def post_speechandtextanalytics_sentimentfeedback(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/sentimentfeedback', params=params, body=body, **kwargs)

    def delete_speechandtextanalytics_sentimentfeedback_sentiment_feedback_id(self, sentiment_feedback_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/speechandtextanalytics/sentimentfeedback/{quote(str(sentiment_feedback_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/settings', params=params, **kwargs)

    def patch_speechandtextanalytics_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/speechandtextanalytics/settings', params=params, body=body, **kwargs)

    def put_speechandtextanalytics_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/speechandtextanalytics/settings', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/topics', params=params, **kwargs)

    def post_speechandtextanalytics_topics(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/topics', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topics_dialects(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/topics/dialects', params=params, **kwargs)

    def get_speechandtextanalytics_topics_general(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/topics/general', params=params, **kwargs)

    def get_speechandtextanalytics_topics_general_status(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/topics/general/status', params=params, **kwargs)

    def post_speechandtextanalytics_topics_generatedphrases_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/topics/generatedphrases/jobs', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topics_generatedphrases_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/topics/generatedphrases/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_speechandtextanalytics_topics_publishjobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/topics/publishjobs', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topics_publishjob(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/topics/publishjobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_speechandtextanalytics_topics_testphrase_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/topics/testphrase/jobs', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topics_testphrase_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/topics/testphrase/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def delete_speechandtextanalytics_topic(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/speechandtextanalytics/topics/{quote(str(topic_id), safe='')}", params=params, body=body, **kwargs)

    def get_speechandtextanalytics_topic(self, topic_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/topics/{quote(str(topic_id), safe='')}", params=params, **kwargs)

    def put_speechandtextanalytics_topic(self, topic_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/speechandtextanalytics/topics/{quote(str(topic_id), safe='')}", params=params, body=body, **kwargs)

    def post_speechandtextanalytics_transcripts_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/speechandtextanalytics/transcripts/search', params=params, body=body, **kwargs)

    def get_speechandtextanalytics_translations_languages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/speechandtextanalytics/translations/languages', params=params, **kwargs)

    def get_speechandtextanalytics_translations_language_conversation(self, conversation_id, language_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/speechandtextanalytics/translations/languages/{quote(str(language_id), safe='')}/conversations/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def get_stations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/stations', params=params, **kwargs)

    def get_station(self, station_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/stations/{quote(str(station_id), safe='')}", params=params, **kwargs)

    def delete_station_associateduser(self, station_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/stations/{quote(str(station_id), safe='')}/associateduser", params=params, body=body, **kwargs)

    def get_systempresences(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/systempresences', params=params, **kwargs)

    def post_taskmanagement_workbins(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workbins', params=params, body=body, **kwargs)

    def post_taskmanagement_workbins_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workbins/query', params=params, body=body, **kwargs)

    def delete_taskmanagement_workbin(self, workbin_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workbin(self, workbin_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_workbin(self, workbin_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workbin_history(self, workbin_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}/history", params=params, **kwargs)

    def get_taskmanagement_workbin_versions(self, workbin_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}/versions", params=params, **kwargs)

    def get_taskmanagement_workbin_version(self, entity_version, workbin_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workbins/{quote(str(workbin_id), safe='')}/versions/{quote(str(entity_version), safe='')}", params=params, **kwargs)

    def post_taskmanagement_workitems(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems', params=params, body=body, **kwargs)

    def post_taskmanagement_workitems_bulk_add_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems/bulk/add/jobs', params=params, body=body, **kwargs)

    def delete_taskmanagement_workitems_bulk_add_job(self, bulk_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/workitems/bulk/add/jobs/{quote(str(bulk_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_bulk_add_job(self, bulk_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/bulk/add/jobs/{quote(str(bulk_job_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_workitems_bulk_add_job(self, bulk_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/bulk/add/jobs/{quote(str(bulk_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_bulk_add_job_results(self, bulk_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/bulk/add/jobs/{quote(str(bulk_job_id), safe='')}/results", params=params, **kwargs)

    def get_taskmanagement_workitems_bulk_jobs_users_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/taskmanagement/workitems/bulk/jobs/users/me', params=params, **kwargs)

    def post_taskmanagement_workitems_bulk_terminate_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems/bulk/terminate/jobs', params=params, body=body, **kwargs)

    def delete_taskmanagement_workitems_bulk_terminate_job(self, bulk_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/workitems/bulk/terminate/jobs/{quote(str(bulk_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_bulk_terminate_job(self, bulk_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/bulk/terminate/jobs/{quote(str(bulk_job_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_workitems_bulk_terminate_job(self, bulk_job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/bulk/terminate/jobs/{quote(str(bulk_job_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_bulk_terminate_job_results(self, bulk_job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/bulk/terminate/jobs/{quote(str(bulk_job_id), safe='')}/results", params=params, **kwargs)

    def post_taskmanagement_workitems_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems/query', params=params, body=body, **kwargs)

    def post_taskmanagement_workitems_query_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems/query/jobs', params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_query_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_taskmanagement_workitems_query_job_results(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/query/jobs/{quote(str(job_id), safe='')}/results", params=params, **kwargs)

    def get_taskmanagement_workitems_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/taskmanagement/workitems/schemas', params=params, **kwargs)

    def post_taskmanagement_workitems_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/workitems/schemas', params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/taskmanagement/workitems/schemas/coretypes', params=params, **kwargs)

    def get_taskmanagement_workitems_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_taskmanagement_workitems_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/taskmanagement/workitems/schemas/limits', params=params, **kwargs)

    def delete_taskmanagement_workitems_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/workitems/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_taskmanagement_workitems_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/taskmanagement/workitems/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitems_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_taskmanagement_workitems_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def delete_taskmanagement_workitem(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_workitem(self, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_workitem(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}", params=params, body=body, **kwargs)

    def post_taskmanagement_workitem_acd_cancel(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/acd/cancel", params=params, body=body, **kwargs)

    def patch_taskmanagement_workitem_assignment(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/assignment", params=params, body=body, **kwargs)

    def post_taskmanagement_workitem_disconnect(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/disconnect", params=params, body=body, **kwargs)

    def get_taskmanagement_workitem_history(self, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/history", params=params, **kwargs)

    def post_taskmanagement_workitem_terminate(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/terminate", params=params, body=body, **kwargs)

    def patch_taskmanagement_workitem_users_me_wrapups(self, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/users/me/wrapups", params=params, body=body, **kwargs)

    def get_taskmanagement_workitem_user_wrapups(self, user_id, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/users/{quote(str(user_id), safe='')}/wrapups", params=params, **kwargs)

    def patch_taskmanagement_workitem_user_wrapups(self, user_id, workitem_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/users/{quote(str(user_id), safe='')}/wrapups", params=params, body=body, **kwargs)

    def get_taskmanagement_workitem_versions(self, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/versions", params=params, **kwargs)

    def get_taskmanagement_workitem_version(self, entity_version, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/versions/{quote(str(entity_version), safe='')}", params=params, **kwargs)

    def get_taskmanagement_workitem_wrapups(self, workitem_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/workitems/{quote(str(workitem_id), safe='')}/wrapups", params=params, **kwargs)

    def post_taskmanagement_worktypes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/worktypes', params=params, body=body, **kwargs)

    def post_taskmanagement_worktypes_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/taskmanagement/worktypes/query', params=params, body=body, **kwargs)

    def delete_taskmanagement_worktype(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_worktype(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_datebased_rules(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/datebased/rules", params=params, **kwargs)

    def post_taskmanagement_worktype_flows_datebased_rules(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/datebased/rules", params=params, body=body, **kwargs)

    def delete_taskmanagement_worktype_flows_datebased_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/datebased/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_datebased_rule(self, rule_id, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/datebased/rules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_worktype_flows_datebased_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/datebased/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_onattributechange_rules(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/onattributechange/rules", params=params, **kwargs)

    def post_taskmanagement_worktype_flows_onattributechange_rules(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/onattributechange/rules", params=params, body=body, **kwargs)

    def delete_taskmanagement_worktype_flows_onattributechange_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/onattributechange/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_onattributechange_rule(self, rule_id, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/onattributechange/rules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_worktype_flows_onattributechange_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/onattributechange/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_oncreate_rules(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/oncreate/rules", params=params, **kwargs)

    def post_taskmanagement_worktype_flows_oncreate_rules(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/oncreate/rules", params=params, body=body, **kwargs)

    def delete_taskmanagement_worktype_flows_oncreate_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/oncreate/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_flows_oncreate_rule(self, rule_id, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/oncreate/rules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_worktype_flows_oncreate_rule(self, rule_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/flows/oncreate/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_history(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/history", params=params, **kwargs)

    def get_taskmanagement_worktype_statuses(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/statuses", params=params, **kwargs)

    def post_taskmanagement_worktype_statuses(self, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/statuses", params=params, body=body, **kwargs)

    def delete_taskmanagement_worktype_status(self, status_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/statuses/{quote(str(status_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_status(self, status_id, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/statuses/{quote(str(status_id), safe='')}", params=params, **kwargs)

    def patch_taskmanagement_worktype_status(self, status_id, worktype_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/statuses/{quote(str(status_id), safe='')}", params=params, body=body, **kwargs)

    def get_taskmanagement_worktype_versions(self, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/versions", params=params, **kwargs)

    def get_taskmanagement_worktype_version(self, entity_version, worktype_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/taskmanagement/worktypes/{quote(str(worktype_id), safe='')}/versions/{quote(str(entity_version), safe='')}", params=params, **kwargs)

    def get_teams(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/teams', params=params, **kwargs)

    def post_teams(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/teams', params=params, body=body, **kwargs)

    def post_teams_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/teams/search', params=params, body=body, **kwargs)

    def delete_team(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/teams/{quote(str(team_id), safe='')}", params=params, body=body, **kwargs)

    def get_team(self, team_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/teams/{quote(str(team_id), safe='')}", params=params, **kwargs)

    def patch_team(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/teams/{quote(str(team_id), safe='')}", params=params, body=body, **kwargs)

    def delete_team_members(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/teams/{quote(str(team_id), safe='')}/members", params=params, body=body, **kwargs)

    def get_team_members(self, team_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/teams/{quote(str(team_id), safe='')}/members", params=params, **kwargs)

    def post_team_members(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/teams/{quote(str(team_id), safe='')}/members", params=params, body=body, **kwargs)

    def get_telephony_agents_greetings_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/agents/greetings/me', params=params, **kwargs)

    def put_telephony_agents_greetings_me(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/telephony/agents/greetings/me', params=params, body=body, **kwargs)

    def get_telephony_agent_greetings(self, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/agents/{quote(str(agent_id), safe='')}/greetings", params=params, **kwargs)

    def put_telephony_agent_greetings(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/agents/{quote(str(agent_id), safe='')}/greetings", params=params, body=body, **kwargs)

    def get_telephony_calls_metrics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/calls/metrics', params=params, **kwargs)

    def get_telephony_mediaregions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/mediaregions', params=params, **kwargs)

    def get_telephony_numbers_routing(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/numbers/routing', params=params, **kwargs)

    def post_telephony_numbers_routing(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/numbers/routing', params=params, body=body, **kwargs)

    def post_telephony_numbers_routing_all(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/numbers/routing/all', params=params, body=body, **kwargs)

    def post_telephony_numbers_routing_reset(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/numbers/routing/reset', params=params, body=body, **kwargs)

    def get_telephony_organization_link(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/organization/link', params=params, **kwargs)

    def post_telephony_organization_link(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/organization/link', params=params, body=body, **kwargs)

    def patch_telephony_organization_link_approve_requesting_organization_id(self, requesting_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/telephony/organization/link/approve/{quote(str(requesting_organization_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_organization_link_regions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/organization/link/regions', params=params, **kwargs)

    def delete_telephony_organization_link_target_organization_id(self, target_organization_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/organization/link/{quote(str(target_organization_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_prefixes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/prefixes', params=params, **kwargs)

    def post_telephony_prefixes_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/prefixes/bulk', params=params, body=body, **kwargs)

    def get_telephony_prefixes_simulate_call(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/prefixes/simulate/call', params=params, **kwargs)

    def get_telephony_providers_edges(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges', params=params, **kwargs)

    def post_telephony_providers_edges(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges', params=params, body=body, **kwargs)

    def post_telephony_providers_edges_addressvalidation(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/addressvalidation', params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_alertablepresences(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/telephony/providers/edges/alertablepresences', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_alertablepresences(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/alertablepresences', params=params, **kwargs)

    def put_telephony_providers_edges_alertablepresences(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/telephony/providers/edges/alertablepresences', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_certificateauthorities(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/certificateauthorities', params=params, **kwargs)

    def post_telephony_providers_edges_certificateauthorities(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/certificateauthorities', params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_certificateauthority(self, certificate_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/certificateauthorities/{quote(str(certificate_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_certificateauthority(self, certificate_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/certificateauthorities/{quote(str(certificate_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_certificateauthority(self, certificate_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/certificateauthorities/{quote(str(certificate_id), safe='')}", params=params, body=body, **kwargs)

    def post_telephony_providers_edges_didpools(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/didpools', params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_didpool(self, did_pool_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/didpools/{quote(str(did_pool_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_didpool(self, did_pool_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/didpools/{quote(str(did_pool_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_didpool(self, did_pool_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/didpools/{quote(str(did_pool_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_did(self, did_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/dids/{quote(str(did_id), safe='')}", params=params, **kwargs)

    def post_telephony_providers_edges_edgegroups(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/edgegroups', params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_edgegroup(self, edge_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/edgegroups/{quote(str(edge_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_edgegroup(self, edge_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/edgegroups/{quote(str(edge_group_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_edgegroup(self, edge_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/edgegroups/{quote(str(edge_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_edgegroup_edgetrunkbase(self, edgegroup_id, edgetrunkbase_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/edgegroups/{quote(str(edgegroup_id), safe='')}/edgetrunkbases/{quote(str(edgetrunkbase_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_edgegroup_edgetrunkbase(self, edgegroup_id, edgetrunkbase_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/edgegroups/{quote(str(edgegroup_id), safe='')}/edgetrunkbases/{quote(str(edgetrunkbase_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_edgeversionreport(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/edgeversionreport', params=params, **kwargs)

    def get_telephony_providers_edges_expired(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/expired', params=params, **kwargs)

    def get_telephony_providers_edges_extensionpools(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/extensionpools', params=params, **kwargs)

    def post_telephony_providers_edges_extensionpools(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/extensionpools', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_extensionpools_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/extensionpools/divisionviews', params=params, **kwargs)

    def delete_telephony_providers_edges_extensionpool(self, extension_pool_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/extensionpools/{quote(str(extension_pool_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_extensionpool(self, extension_pool_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/extensionpools/{quote(str(extension_pool_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_extensionpool(self, extension_pool_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/extensionpools/{quote(str(extension_pool_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_extensions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/extensions', params=params, **kwargs)

    def get_telephony_providers_edges_extension(self, extension_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/extensions/{quote(str(extension_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_linebasesettings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/linebasesettings', params=params, **kwargs)

    def get_telephony_providers_edges_linebasesetting(self, line_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/linebasesettings/{quote(str(line_base_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_lines(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/lines', params=params, **kwargs)

    def get_telephony_providers_edges_lines_template(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/lines/template', params=params, **kwargs)

    def get_telephony_providers_edges_line(self, line_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/lines/{quote(str(line_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_logicalinterfaces(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/logicalinterfaces', params=params, **kwargs)

    def get_telephony_providers_edges_metrics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/metrics', params=params, **kwargs)

    def get_telephony_providers_edges_phonebasesettings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/phonebasesettings', params=params, **kwargs)

    def post_telephony_providers_edges_phonebasesettings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/phonebasesettings', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_phonebasesettings_availablemetabases(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/phonebasesettings/availablemetabases', params=params, **kwargs)

    def get_telephony_providers_edges_phonebasesettings_template(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/phonebasesettings/template', params=params, **kwargs)

    def delete_telephony_providers_edges_phonebasesetting(self, phone_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/phonebasesettings/{quote(str(phone_base_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_phonebasesetting(self, phone_base_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/phonebasesettings/{quote(str(phone_base_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_phonebasesetting(self, phone_base_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/phonebasesettings/{quote(str(phone_base_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_phones(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/phones', params=params, **kwargs)

    def post_telephony_providers_edges_phones(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/phones', params=params, body=body, **kwargs)

    def post_telephony_providers_edges_phones_reboot(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/phones/reboot', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_phones_template(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/phones/template', params=params, **kwargs)

    def delete_telephony_providers_edges_phone(self, phone_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/phones/{quote(str(phone_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_phone(self, phone_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/phones/{quote(str(phone_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_phone(self, phone_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/phones/{quote(str(phone_id), safe='')}", params=params, body=body, **kwargs)

    def post_telephony_providers_edges_phone_reboot(self, phone_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/phones/{quote(str(phone_id), safe='')}/reboot", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_physicalinterfaces(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/physicalinterfaces', params=params, **kwargs)

    def post_telephony_providers_edges_sites(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/sites', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_sites_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/sites/search', params=params, **kwargs)

    def post_telephony_providers_edges_sites_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/sites/search', params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_site(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_site(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_site(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_site_numberplans(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/numberplans", params=params, **kwargs)

    def put_telephony_providers_edges_site_numberplans(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/numberplans", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_site_numberplans_classifications(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/numberplans/classifications", params=params, **kwargs)

    def get_telephony_providers_edges_site_numberplan(self, number_plan_id, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/numberplans/{quote(str(number_plan_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_site_outboundroutes(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/outboundroutes", params=params, **kwargs)

    def post_telephony_providers_edges_site_outboundroutes(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/outboundroutes", params=params, body=body, **kwargs)

    def delete_telephony_providers_edges_site_outboundroute(self, outbound_route_id, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/outboundroutes/{quote(str(outbound_route_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_site_outboundroute(self, outbound_route_id, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/outboundroutes/{quote(str(outbound_route_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_site_outboundroute(self, outbound_route_id, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/outboundroutes/{quote(str(outbound_route_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_site_siteconnections(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/siteconnections", params=params, **kwargs)

    def patch_telephony_providers_edges_site_siteconnections(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/siteconnections", params=params, body=body, **kwargs)

    def put_telephony_providers_edges_site_siteconnections(self, site_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/sites/{quote(str(site_id), safe='')}/siteconnections", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_timezones(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/timezones', params=params, **kwargs)

    def get_telephony_providers_edges_trunkbasesettings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunkbasesettings', params=params, **kwargs)

    def post_telephony_providers_edges_trunkbasesettings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/trunkbasesettings', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_trunkbasesettings_availablemetabases(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunkbasesettings/availablemetabases', params=params, **kwargs)

    def post_telephony_providers_edges_trunkbasesettings_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/trunkbasesettings/search', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_trunkbasesettings_site_site_id(self, site_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/trunkbasesettings/site/{quote(str(site_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_trunkbasesettings_template(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunkbasesettings/template', params=params, **kwargs)

    def delete_telephony_providers_edges_trunkbasesetting(self, trunk_base_settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/trunkbasesettings/{quote(str(trunk_base_settings_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_trunkbasesetting(self, trunk_base_settings_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/trunkbasesettings/{quote(str(trunk_base_settings_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edges_trunkbasesetting(self, trunk_base_settings_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/trunkbasesettings/{quote(str(trunk_base_settings_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edges_trunks(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunks', params=params, **kwargs)

    def get_telephony_providers_edges_trunks_metrics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunks/metrics', params=params, **kwargs)

    def post_telephony_providers_edges_trunks_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/providers/edges/trunks/search', params=params, body=body, **kwargs)

    def get_telephony_providers_edges_trunk(self, trunk_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/trunks/{quote(str(trunk_id), safe='')}", params=params, **kwargs)

    def get_telephony_providers_edges_trunk_metrics(self, trunk_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/trunks/{quote(str(trunk_id), safe='')}/metrics", params=params, **kwargs)

    def get_telephony_providers_edges_trunkswithrecording(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/providers/edges/trunkswithrecording', params=params, **kwargs)

    def delete_telephony_providers_edge(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edge(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edge(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_diagnostic_nslookup(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/nslookup", params=params, **kwargs)

    def post_telephony_providers_edge_diagnostic_nslookup(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/nslookup", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_diagnostic_ping(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/ping", params=params, **kwargs)

    def post_telephony_providers_edge_diagnostic_ping(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/ping", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_diagnostic_route(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/route", params=params, **kwargs)

    def post_telephony_providers_edge_diagnostic_route(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/route", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_diagnostic_tracepath(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/tracepath", params=params, **kwargs)

    def post_telephony_providers_edge_diagnostic_tracepath(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/diagnostic/tracepath", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_logicalinterfaces(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logicalinterfaces", params=params, **kwargs)

    def post_telephony_providers_edge_logicalinterfaces(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logicalinterfaces", params=params, body=body, **kwargs)

    def delete_telephony_providers_edge_logicalinterface(self, edge_id, interface_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logicalinterfaces/{quote(str(interface_id), safe='')}", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_logicalinterface(self, edge_id, interface_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logicalinterfaces/{quote(str(interface_id), safe='')}", params=params, **kwargs)

    def put_telephony_providers_edge_logicalinterface(self, edge_id, interface_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logicalinterfaces/{quote(str(interface_id), safe='')}", params=params, body=body, **kwargs)

    def post_telephony_providers_edge_logs_jobs(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logs/jobs", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_logs_job(self, edge_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logs/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_telephony_providers_edge_logs_job_upload(self, edge_id, job_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/logs/jobs/{quote(str(job_id), safe='')}/upload", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_metrics(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/metrics", params=params, **kwargs)

    def post_telephony_providers_edge_offlineconfiguration(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/offlineconfiguration", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_physicalinterfaces(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/physicalinterfaces", params=params, **kwargs)

    def get_telephony_providers_edge_physicalinterface(self, edge_id, interface_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/physicalinterfaces/{quote(str(interface_id), safe='')}", params=params, **kwargs)

    def post_telephony_providers_edge_reboot(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/reboot", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_setuppackage(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/setuppackage", params=params, **kwargs)

    def delete_telephony_providers_edge_softwareupdate(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/softwareupdate", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_softwareupdate(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/softwareupdate", params=params, **kwargs)

    def post_telephony_providers_edge_softwareupdate(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/softwareupdate", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_softwareversions(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/softwareversions", params=params, **kwargs)

    def post_telephony_providers_edge_statuscode(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/statuscode", params=params, body=body, **kwargs)

    def get_telephony_providers_edge_trunks(self, edge_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/trunks", params=params, **kwargs)

    def post_telephony_providers_edge_unpair(self, edge_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/telephony/providers/edges/{quote(str(edge_id), safe='')}/unpair", params=params, body=body, **kwargs)

    def put_telephony_settings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/telephony/settings', params=params, body=body, **kwargs)

    def get_telephony_sipmessages_conversation(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/sipmessages/conversations/{quote(str(conversation_id), safe='')}", params=params, **kwargs)

    def get_telephony_sipmessages_conversation_headers(self, conversation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/sipmessages/conversations/{quote(str(conversation_id), safe='')}/headers", params=params, **kwargs)

    def get_telephony_siptraces(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/telephony/siptraces', params=params, **kwargs)

    def post_telephony_siptraces_download(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/telephony/siptraces/download', params=params, body=body, **kwargs)

    def get_telephony_siptraces_download_download_id(self, download_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/telephony/siptraces/download/{quote(str(download_id), safe='')}", params=params, **kwargs)

    def post_textbots_botflows_sessions(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/textbots/botflows/sessions', params=params, body=body, **kwargs)

    def post_textbots_botflows_session_turns(self, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/textbots/botflows/sessions/{quote(str(session_id), safe='')}/turns", params=params, body=body, **kwargs)

    def post_textbots_bots_execute(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/textbots/bots/execute', params=params, body=body, **kwargs)

    def get_textbots_bots_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/textbots/bots/search', params=params, **kwargs)

    def get_timezones(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/timezones', params=params, **kwargs)

    def get_tokens_timeout(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/tokens/timeout', params=params, **kwargs)

    def put_tokens_timeout(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/tokens/timeout', params=params, body=body, **kwargs)

    def delete_token(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/tokens/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def post_uploads_learning_coverart(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/uploads/learning/coverart', params=params, body=body, **kwargs)

    def post_uploads_publicassets_images(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/uploads/publicassets/images', params=params, body=body, **kwargs)

    def post_uploads_recordings(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/uploads/recordings', params=params, body=body, **kwargs)

    def post_uploads_workforcemanagement_historicaldata_csv(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/uploads/workforcemanagement/historicaldata/csv', params=params, body=body, **kwargs)

    def post_usage_aggregates_query_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/usage/aggregates/query/jobs', params=params, body=body, **kwargs)

    def get_usage_aggregates_query_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/usage/aggregates/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_usage_client_client_id_aggregates_query_jobs(self, client_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/usage/client/{quote(str(client_id), safe='')}/aggregates/query/jobs", params=params, body=body, **kwargs)

    def get_usage_client_client_id_aggregates_query_job(self, client_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/usage/client/{quote(str(client_id), safe='')}/aggregates/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_usage_events_definitions(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/usage/events/definitions', params=params, **kwargs)

    def get_usage_events_definition(self, event_definition_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/usage/events/definitions/{quote(str(event_definition_id), safe='')}", params=params, **kwargs)

    def post_usage_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/usage/query', params=params, body=body, **kwargs)

    def get_usage_query_execution_id_results(self, execution_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/usage/query/{quote(str(execution_id), safe='')}/results", params=params, **kwargs)

    def post_usage_simplesearch(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/usage/simplesearch', params=params, body=body, **kwargs)

    def get_usage_simplesearch_execution_id_results(self, execution_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/usage/simplesearch/{quote(str(execution_id), safe='')}/results", params=params, **kwargs)

    def get_userrecordings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/userrecordings', params=params, **kwargs)

    def get_userrecordings_summary(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/userrecordings/summary', params=params, **kwargs)

    def delete_userrecording(self, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/userrecordings/{quote(str(recording_id), safe='')}", params=params, body=body, **kwargs)

    def get_userrecording(self, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/userrecordings/{quote(str(recording_id), safe='')}", params=params, **kwargs)

    def put_userrecording(self, recording_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/userrecordings/{quote(str(recording_id), safe='')}", params=params, body=body, **kwargs)

    def get_userrecording_transcoding(self, recording_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/userrecordings/{quote(str(recording_id), safe='')}/transcoding", params=params, **kwargs)

    def delete_users_agentui_agents_autoanswer_agent_id_settings(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/agentui/agents/autoanswer/{quote(str(agent_id), safe='')}/settings", params=params, body=body, **kwargs)

    def get_users_agentui_agents_autoanswer_agent_id_settings(self, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/agentui/agents/autoanswer/{quote(str(agent_id), safe='')}/settings", params=params, **kwargs)

    def patch_users_agentui_agents_autoanswer_agent_id_settings(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/agentui/agents/autoanswer/{quote(str(agent_id), safe='')}/settings", params=params, body=body, **kwargs)

    def put_users_agentui_agents_autoanswer_agent_id_settings(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/agentui/agents/autoanswer/{quote(str(agent_id), safe='')}/settings", params=params, body=body, **kwargs)

    def patch_users_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/users/bulk', params=params, body=body, **kwargs)

    def get_users_chats_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/chats/me', params=params, **kwargs)

    def get_users_customattributes_schemas(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/customattributes/schemas', params=params, **kwargs)

    def post_users_customattributes_schemas(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/customattributes/schemas', params=params, body=body, **kwargs)

    def get_users_customattributes_schemas_coretypes(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/customattributes/schemas/coretypes', params=params, **kwargs)

    def get_users_customattributes_schemas_coretype(self, core_type_name, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/customattributes/schemas/coretypes/{quote(str(core_type_name), safe='')}", params=params, **kwargs)

    def get_users_customattributes_schemas_limits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/customattributes/schemas/limits', params=params, **kwargs)

    def delete_users_customattributes_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/customattributes/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_users_customattributes_schema(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/customattributes/schemas/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def put_users_customattributes_schema(self, schema_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/customattributes/schemas/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_users_customattributes_schema_versions(self, schema_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/customattributes/schemas/{quote(str(schema_id), safe='')}/versions", params=params, **kwargs)

    def get_users_customattributes_schema_version(self, schema_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/customattributes/schemas/{quote(str(schema_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def get_users_development_activities(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/development/activities', params=params, **kwargs)

    def post_users_development_activities_aggregates_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/development/activities/aggregates/query', params=params, body=body, **kwargs)

    def get_users_development_activities_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/development/activities/me', params=params, **kwargs)

    def get_users_development_activity(self, activity_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/development/activities/{quote(str(activity_id), safe='')}", params=params, **kwargs)

    def get_users_externalid_authority_name_external_key(self, authority_name, external_key, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/externalid/{quote(str(authority_name), safe='')}/{quote(str(external_key), safe='')}", params=params, **kwargs)

    def post_users_me_password(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/me/password', params=params, body=body, **kwargs)

    def get_users_me_verifiers(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/me/verifiers', params=params, **kwargs)

    def post_users_me_verifiers_totp(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/me/verifiers/totp', params=params, body=body, **kwargs)

    def post_users_me_verifiers_totp_verifier_id(self, verifier_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/me/verifiers/totp/{quote(str(verifier_id), safe='')}", params=params, body=body, **kwargs)

    def post_users_me_verifiers_webauthn_register(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/me/verifiers/webauthn/register', params=params, body=body, **kwargs)

    def post_users_me_verifiers_webauthn_register_options(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/me/verifiers/webauthn/register/options', params=params, body=body, **kwargs)

    def delete_users_me_verifier(self, verifier_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/me/verifiers/{quote(str(verifier_id), safe='')}", params=params, body=body, **kwargs)

    def put_users_me_verifier(self, verifier_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/me/verifiers/{quote(str(verifier_id), safe='')}", params=params, body=body, **kwargs)

    def put_users_presences_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/users/presences/bulk', params=params, body=body, **kwargs)

    def get_users_presences_purecloud_bulk(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/presences/purecloud/bulk', params=params, **kwargs)

    def get_users_presence_bulk(self, source_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/presences/{quote(str(source_id), safe='')}/bulk", params=params, **kwargs)

    def get_users_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/query', params=params, **kwargs)

    def get_users_rules(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/rules', params=params, **kwargs)

    def post_users_rules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/rules', params=params, body=body, **kwargs)

    def post_users_rules_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/rules/query', params=params, body=body, **kwargs)

    def get_users_rules_setting(self, rule_type, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/rules/settings/{quote(str(rule_type), safe='')}", params=params, **kwargs)

    def delete_users_rule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_users_rule(self, rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/rules/{quote(str(rule_id), safe='')}", params=params, **kwargs)

    def patch_users_rule(self, rule_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/rules/{quote(str(rule_id), safe='')}", params=params, body=body, **kwargs)

    def get_users_rule_dependents(self, rule_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/rules/{quote(str(rule_id), safe='')}/dependents", params=params, **kwargs)

    def get_users_rule_dependent_type_id(self, rule_id, rule_type, type_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/rules/{quote(str(rule_id), safe='')}/dependents/{quote(str(rule_type), safe='')}/{quote(str(type_id), safe='')}", params=params, **kwargs)

    def get_users_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/search', params=params, **kwargs)

    def post_users_search_teams_assign(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/users/search/teams/assign', params=params, body=body, **kwargs)

    def get_users_stations_me(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/users/stations/me', params=params, **kwargs)

    def delete_users_stations_me_associatedstation(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/users/stations/me/associatedstation', params=params, body=body, **kwargs)

    def put_users_stations_me_associatedstation_station_id(self, station_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/stations/me/associatedstation/{quote(str(station_id), safe='')}", params=params, body=body, **kwargs)

    def delete_user(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_adjacents(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/adjacents", params=params, **kwargs)

    def get_user_callforwarding(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/callforwarding", params=params, **kwargs)

    def patch_user_callforwarding(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/callforwarding", params=params, body=body, **kwargs)

    def put_user_callforwarding(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/callforwarding", params=params, body=body, **kwargs)

    def patch_user_customattributes(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes", params=params, body=body, **kwargs)

    def put_user_customattributes(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes", params=params, body=body, **kwargs)

    def get_user_customattributes_bulk(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes/bulk", params=params, **kwargs)

    def patch_user_customattributes_bulk(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes/bulk", params=params, body=body, **kwargs)

    def delete_user_customattribute(self, schema_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes/{quote(str(schema_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_customattribute(self, schema_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/customattributes/{quote(str(schema_id), safe='')}", params=params, **kwargs)

    def get_user_directreports(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/directreports", params=params, **kwargs)

    def get_user_externalid(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/externalid", params=params, **kwargs)

    def post_user_externalid(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/externalid", params=params, body=body, **kwargs)

    def get_user_externalid_authority_name(self, authority_name, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/externalid/{quote(str(authority_name), safe='')}", params=params, **kwargs)

    def delete_user_externalid_authority_name_external_key(self, authority_name, external_key, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/externalid/{quote(str(authority_name), safe='')}/{quote(str(external_key), safe='')}", params=params, body=body, **kwargs)

    def get_user_favorites(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/favorites", params=params, **kwargs)

    def get_user_geolocation(self, client_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/geolocations/{quote(str(client_id), safe='')}", params=params, **kwargs)

    def patch_user_geolocation(self, client_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/geolocations/{quote(str(client_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_greetings(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/greetings", params=params, **kwargs)

    def post_user_greetings(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/greetings", params=params, body=body, **kwargs)

    def get_user_greetings_defaults(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/greetings/defaults", params=params, **kwargs)

    def put_user_greetings_defaults(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/greetings/defaults", params=params, body=body, **kwargs)

    def post_user_invite(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/invite", params=params, body=body, **kwargs)

    def get_user_outofoffice(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/outofoffice", params=params, **kwargs)

    def put_user_outofoffice(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/outofoffice", params=params, body=body, **kwargs)

    def get_user_presences_purecloud(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/presences/purecloud", params=params, **kwargs)

    def patch_user_presences_purecloud(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/presences/purecloud", params=params, body=body, **kwargs)

    def get_user_presence(self, source_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/presences/{quote(str(source_id), safe='')}", params=params, **kwargs)

    def patch_user_presence(self, source_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/presences/{quote(str(source_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_profile(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/profile", params=params, **kwargs)

    def get_user_profileskills(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/profileskills", params=params, **kwargs)

    def put_user_profileskills(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/profileskills", params=params, body=body, **kwargs)

    def get_user_queues(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/queues", params=params, **kwargs)

    def patch_user_queues(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/queues", params=params, body=body, **kwargs)

    def patch_user_queue(self, queue_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/queues/{quote(str(queue_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_routinglanguages(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/routinglanguages", params=params, **kwargs)

    def post_user_routinglanguages(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/routinglanguages", params=params, body=body, **kwargs)

    def patch_user_routinglanguages_bulk(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/routinglanguages/bulk", params=params, body=body, **kwargs)

    def delete_user_routinglanguage(self, language_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/routinglanguages/{quote(str(language_id), safe='')}", params=params, body=body, **kwargs)

    def patch_user_routinglanguage(self, language_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/routinglanguages/{quote(str(language_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_routingskills(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills", params=params, **kwargs)

    def post_user_routingskills(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills", params=params, body=body, **kwargs)

    def patch_user_routingskills_bulk(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills/bulk", params=params, body=body, **kwargs)

    def put_user_routingskills_bulk(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills/bulk", params=params, body=body, **kwargs)

    def delete_user_routingskill(self, skill_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills/{quote(str(skill_id), safe='')}", params=params, body=body, **kwargs)

    def put_user_routingskill(self, skill_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/routingskills/{quote(str(skill_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_routingstatus(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/routingstatus", params=params, **kwargs)

    def put_user_routingstatus(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/routingstatus", params=params, body=body, **kwargs)

    def post_user_screenmonitors_sessions(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/users/{quote(str(user_id), safe='')}/screenmonitors/sessions", params=params, body=body, **kwargs)

    def delete_user_screenmonitors_session(self, screen_monitoring_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/screenmonitors/sessions/{quote(str(screen_monitoring_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_screenmonitors_session(self, screen_monitoring_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/screenmonitors/sessions/{quote(str(screen_monitoring_id), safe='')}", params=params, **kwargs)

    def get_user_skillgroups(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/skillgroups", params=params, **kwargs)

    def get_user_state(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/state", params=params, **kwargs)

    def get_user_station(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/station", params=params, **kwargs)

    def delete_user_station_associatedstation(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/station/associatedstation", params=params, body=body, **kwargs)

    def put_user_station_associatedstation_station_id(self, station_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/station/associatedstation/{quote(str(station_id), safe='')}", params=params, body=body, **kwargs)

    def delete_user_station_defaultstation(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/station/defaultstation", params=params, body=body, **kwargs)

    def put_user_station_defaultstation_station_id(self, station_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/station/defaultstation/{quote(str(station_id), safe='')}", params=params, body=body, **kwargs)

    def get_user_superiors(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/superiors", params=params, **kwargs)

    def get_user_trustors(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/trustors", params=params, **kwargs)

    def get_user_verifiers(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/users/{quote(str(user_id), safe='')}/verifiers", params=params, **kwargs)

    def delete_user_verifier(self, user_id, verifier_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/users/{quote(str(user_id), safe='')}/verifiers/{quote(str(verifier_id), safe='')}", params=params, body=body, **kwargs)

    def put_user_verifier(self, user_id, verifier_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/users/{quote(str(user_id), safe='')}/verifiers/{quote(str(verifier_id), safe='')}", params=params, body=body, **kwargs)

    def get_voicemail_group_mailbox(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/groups/{quote(str(group_id), safe='')}/mailbox", params=params, **kwargs)

    def get_voicemail_group_messages(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/groups/{quote(str(group_id), safe='')}/messages", params=params, **kwargs)

    def get_voicemail_group_policy(self, group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/groups/{quote(str(group_id), safe='')}/policy", params=params, **kwargs)

    def patch_voicemail_group_policy(self, group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/voicemail/groups/{quote(str(group_id), safe='')}/policy", params=params, body=body, **kwargs)

    def get_voicemail_mailbox(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/mailbox', params=params, **kwargs)

    def get_voicemail_me_mailbox(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/me/mailbox', params=params, **kwargs)

    def get_voicemail_me_messages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/me/messages', params=params, **kwargs)

    def get_voicemail_me_policy(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/me/policy', params=params, **kwargs)

    def patch_voicemail_me_policy(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/voicemail/me/policy', params=params, body=body, **kwargs)

    def delete_voicemail_messages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/voicemail/messages', params=params, body=body, **kwargs)

    def get_voicemail_messages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/messages', params=params, **kwargs)

    def post_voicemail_messages(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/voicemail/messages', params=params, body=body, **kwargs)

    def delete_voicemail_message(self, message_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/voicemail/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def get_voicemail_message(self, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/messages/{quote(str(message_id), safe='')}", params=params, **kwargs)

    def patch_voicemail_message(self, message_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/voicemail/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def put_voicemail_message(self, message_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/voicemail/messages/{quote(str(message_id), safe='')}", params=params, body=body, **kwargs)

    def get_voicemail_message_media(self, message_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/messages/{quote(str(message_id), safe='')}/media", params=params, **kwargs)

    def get_voicemail_policy(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/policy', params=params, **kwargs)

    def put_voicemail_policy(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', '/api/v2/voicemail/policy', params=params, body=body, **kwargs)

    def get_voicemail_queue_messages(self, queue_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/queues/{quote(str(queue_id), safe='')}/messages", params=params, **kwargs)

    def get_voicemail_search(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/voicemail/search', params=params, **kwargs)

    def post_voicemail_search(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/voicemail/search', params=params, body=body, **kwargs)

    def get_voicemail_userpolicy(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/userpolicies/{quote(str(user_id), safe='')}", params=params, **kwargs)

    def patch_voicemail_userpolicy(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/voicemail/userpolicies/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def put_voicemail_userpolicy(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/voicemail/userpolicies/{quote(str(user_id), safe='')}", params=params, body=body, **kwargs)

    def get_voicemail_user_mailbox(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/users/{quote(str(user_id), safe='')}/mailbox", params=params, **kwargs)

    def get_voicemail_user_messages(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/voicemail/users/{quote(str(user_id), safe='')}/messages", params=params, **kwargs)

    def get_webdeployments_configurations(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/webdeployments/configurations', params=params, **kwargs)

    def post_webdeployments_configurations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/webdeployments/configurations', params=params, body=body, **kwargs)

    def delete_webdeployments_configuration(self, configuration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}", params=params, body=body, **kwargs)

    def get_webdeployments_configuration_versions(self, configuration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}/versions", params=params, **kwargs)

    def get_webdeployments_configuration_versions_draft(self, configuration_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}/versions/draft", params=params, **kwargs)

    def put_webdeployments_configuration_versions_draft(self, configuration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}/versions/draft", params=params, body=body, **kwargs)

    def post_webdeployments_configuration_versions_draft_publish(self, configuration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}/versions/draft/publish", params=params, body=body, **kwargs)

    def get_webdeployments_configuration_version(self, configuration_id, version_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/configurations/{quote(str(configuration_id), safe='')}/versions/{quote(str(version_id), safe='')}", params=params, **kwargs)

    def post_webdeployments_deployments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/webdeployments/deployments', params=params, body=body, **kwargs)

    def delete_webdeployments_deployment(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}", params=params, body=body, **kwargs)

    def get_webdeployments_deployment(self, deployment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}", params=params, **kwargs)

    def put_webdeployments_deployment(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}", params=params, body=body, **kwargs)

    def delete_webdeployments_deployment_cobrowse_session_id(self, deployment_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}/cobrowse/{quote(str(session_id), safe='')}", params=params, body=body, **kwargs)

    def get_webdeployments_deployment_cobrowse_session_id(self, deployment_id, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}/cobrowse/{quote(str(session_id), safe='')}", params=params, **kwargs)

    def get_webdeployments_deployment_configurations(self, deployment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}/configurations", params=params, **kwargs)

    def get_webdeployments_deployment_identityresolution(self, deployment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}/identityresolution", params=params, **kwargs)

    def put_webdeployments_deployment_identityresolution(self, deployment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/webdeployments/deployments/{quote(str(deployment_id), safe='')}/identityresolution", params=params, body=body, **kwargs)

    def post_webdeployments_token_oauthcodegrantjwtexchange(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/webdeployments/token/oauthcodegrantjwtexchange', params=params, body=body, **kwargs)

    def post_webdeployments_token_refresh(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/webdeployments/token/refresh', params=params, body=body, **kwargs)

    def delete_webdeployments_token_revoke(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/webdeployments/token/revoke', params=params, body=body, **kwargs)

    def delete_webmessaging_deployment_pushdevice(self, deployment_id, token_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/webmessaging/deployments/{quote(str(deployment_id), safe='')}/pushdevices/{quote(str(token_id), safe='')}", params=params, body=body, **kwargs)

    def patch_webmessaging_deployment_pushdevice(self, deployment_id, token_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/webmessaging/deployments/{quote(str(deployment_id), safe='')}/pushdevices/{quote(str(token_id), safe='')}", params=params, body=body, **kwargs)

    def post_webmessaging_deployment_pushdevice(self, deployment_id, token_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/webmessaging/deployments/{quote(str(deployment_id), safe='')}/pushdevices/{quote(str(token_id), safe='')}", params=params, body=body, **kwargs)

    def get_webmessaging_messages(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/webmessaging/messages', params=params, **kwargs)

    def get_workforcemanagement_adherence(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/adherence', params=params, **kwargs)

    def post_workforcemanagement_adherence_adjustments(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/adherence/adjustments', params=params, body=body, **kwargs)

    def post_workforcemanagement_adherence_adjustments_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/adherence/adjustments/query', params=params, body=body, **kwargs)

    def delete_workforcemanagement_adherence_adjustment(self, adjustment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/adherence/adjustments/{quote(str(adjustment_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_adherence_adjustment(self, adjustment_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/adherence/adjustments/{quote(str(adjustment_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_adherence_adjustment(self, adjustment_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/adherence/adjustments/{quote(str(adjustment_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_adherence_explanations(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/adherence/explanations', params=params, body=body, **kwargs)

    def get_workforcemanagement_adherence_explanations_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/adherence/explanations/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_adherence_explanations_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/adherence/explanations/query', params=params, body=body, **kwargs)

    def get_workforcemanagement_adherence_explanation(self, explanation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/adherence/explanations/{quote(str(explanation_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_adherence_historical_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/adherence/historical/bulk', params=params, body=body, **kwargs)

    def get_workforcemanagement_adherence_historical_bulk_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/adherence/historical/bulk/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_adherence_historical_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/adherence/historical/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_agents(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents', params=params, body=body, **kwargs)

    def post_workforcemanagement_agents_integrations_hris_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/integrations/hris/query', params=params, body=body, **kwargs)

    def post_workforcemanagement_agents_me_adherence_historical_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/me/adherence/historical/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_agents_me_adherence_historical_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/agents/me/adherence/historical/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_agents_me_managementunit(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/agents/me/managementunit', params=params, **kwargs)

    def post_workforcemanagement_agents_me_possibleworkshifts(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/me/possibleworkshifts', params=params, body=body, **kwargs)

    def post_workforcemanagement_agents_opportunities_enrollments_bulk_add(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/opportunities/enrollments/bulk/add', params=params, body=body, **kwargs)

    def post_workforcemanagement_agents_opportunities_enrollments_bulk_statuses_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/opportunities/enrollments/bulk/statuses/update', params=params, body=body, **kwargs)

    def post_workforcemanagement_agents_opportunities_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agents/opportunities/query', params=params, body=body, **kwargs)

    def post_workforcemanagement_agent_adherence_adjustments_query(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/adjustments/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_agent_adherence_adjustment(self, adjustment_id, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/adjustments/{quote(str(adjustment_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_agent_adherence_adjustment(self, adjustment_id, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/adjustments/{quote(str(adjustment_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_agent_adherence_explanations(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/explanations", params=params, body=body, **kwargs)

    def post_workforcemanagement_agent_adherence_explanations_query(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/explanations/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_agent_adherence_explanation(self, agent_id, explanation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/explanations/{quote(str(explanation_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_agent_adherence_explanation(self, agent_id, explanation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/adherence/explanations/{quote(str(explanation_id), safe='')}", params=params, body=body, **kwargs)

    def put_workforcemanagement_agent_integrations_hris(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/integrations/hris", params=params, body=body, **kwargs)

    def get_workforcemanagement_agent_managementunit(self, agent_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/managementunit", params=params, **kwargs)

    def patch_workforcemanagement_agent_unavailabletimes(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/unavailabletimes", params=params, body=body, **kwargs)

    def post_workforcemanagement_agent_unavailabletimes_query(self, agent_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/agents/{quote(str(agent_id), safe='')}/unavailabletimes/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_agentschedules_managementunits_mine(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agentschedules/managementunits/mine', params=params, body=body, **kwargs)

    def post_workforcemanagement_agentschedules_mine(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/agentschedules/mine', params=params, body=body, **kwargs)

    def post_workforcemanagement_alternativeshifts_offers_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/alternativeshifts/offers/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_alternativeshifts_offers_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/alternativeshifts/offers/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_alternativeshifts_offers_search_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/alternativeshifts/offers/search/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_alternativeshifts_offers_search_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/alternativeshifts/offers/search/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_alternativeshifts_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/alternativeshifts/settings', params=params, **kwargs)

    def get_workforcemanagement_alternativeshifts_trades(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/alternativeshifts/trades', params=params, **kwargs)

    def post_workforcemanagement_alternativeshifts_trades(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/alternativeshifts/trades', params=params, body=body, **kwargs)

    def get_workforcemanagement_alternativeshifts_trades_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/alternativeshifts/trades/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_alternativeshifts_trades_state_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/workforcemanagement/alternativeshifts/trades/state/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_alternativeshifts_trades_state_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/alternativeshifts/trades/state/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_alternativeshifts_trade(self, trade_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/alternativeshifts/trades/{quote(str(trade_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_alternativeshifts_trade(self, trade_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/alternativeshifts/trades/{quote(str(trade_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/businessunits', params=params, **kwargs)

    def post_workforcemanagement_businessunits(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/businessunits', params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunits_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/businessunits/divisionviews', params=params, **kwargs)

    def delete_workforcemanagement_businessunit(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activitycodes(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activitycodes(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes", params=params, body=body, **kwargs)

    def patch_workforcemanagement_businessunit_activitycodes_bulk(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes/bulk", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_activitycode(self, activity_code_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes/{quote(str(activity_code_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activitycode(self, activity_code_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes/{quote(str(activity_code_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_activitycode(self, activity_code_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activitycodes/{quote(str(activity_code_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplans(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activityplans(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplans_jobs(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/jobs", params=params, **kwargs)

    def get_workforcemanagement_businessunit_activityplan(self, activity_plan_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_activityplan(self, activity_plan_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_activityplan_deletions_jobs(self, activity_plan_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/deletions/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_deletions_job(self, activity_plan_id, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/deletions/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_jobs(self, activity_plan_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/jobs", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activityplan_occurrences_deletions_jobs(self, activity_plan_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/deletions/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_occurrences_deletions_job(self, activity_plan_id, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/deletions/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activityplan_occurrence_sessions_deletions_jobs(self, activity_plan_id, business_unit_id, occurrence_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/{quote(str(occurrence_id), safe='')}/sessions/deletions/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_occurrence_sessions_deletions_job(self, activity_plan_id, business_unit_id, job_id, occurrence_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/{quote(str(occurrence_id), safe='')}/sessions/deletions/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activityplan_occurrence_session_users_deletions_jobs(self, activity_plan_id, business_unit_id, occurrence_id, session_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/{quote(str(occurrence_id), safe='')}/sessions/{quote(str(session_id), safe='')}/users/deletions/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_occurrence_session_users_deletions_job(self, activity_plan_id, business_unit_id, job_id, occurrence_id, session_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/occurrences/{quote(str(occurrence_id), safe='')}/sessions/{quote(str(session_id), safe='')}/users/deletions/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_activityplan_runs_jobs(self, activity_plan_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/runs/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_activityplan_runs_job(self, activity_plan_id, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/activityplans/{quote(str(activity_plan_id), safe='')}/runs/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_bulk(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/bulk", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_adherence_adjustments_bulk(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/bulk", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_adherence_adjustments_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_query_jobs(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/query/jobs", params=params, **kwargs)

    def post_workforcemanagement_businessunit_adherence_adjustments_query_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/query/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_query_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_reasoncodes(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes", params=params, **kwargs)

    def post_workforcemanagement_businessunit_adherence_adjustments_reasoncodes(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_adherence_adjustments_reasoncodes_bulk(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/bulk", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_reasoncodes_bulk(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/bulk", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_adherence_adjustments_reasoncodes_bulk(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/bulk", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_adherence_adjustments_reasoncodes_bulk(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/bulk", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_adherence_adjustments_reasoncode(self, business_unit_id, reason_code_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/{quote(str(reason_code_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_reasoncode(self, business_unit_id, reason_code_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/{quote(str(reason_code_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_adherence_adjustments_reasoncode(self, business_unit_id, reason_code_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/reasoncodes/{quote(str(reason_code_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_adherence_adjustments_settings(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/settings", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_adherence_adjustments_settings(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/adjustments/settings", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_adherence_explanations_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/adherence/explanations/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_agentschedules_search(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/agentschedules/search", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_alternativeshifts_settings(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/alternativeshifts/settings", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_alternativeshifts_settings(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/alternativeshifts/settings", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_alternativeshifts_trades_search(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/alternativeshifts/trades/search", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_alternativeshifts_trades_search_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/alternativeshifts/trades/search/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_alternativeshifts_trade(self, business_unit_id, trade_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/alternativeshifts/trades/{quote(str(trade_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_capacityplanning_longtermrequirements_automaticbestmethod_week_forecast(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplanning/longtermrequirements/automaticbestmethod/weeks/{quote(str(week_date_id), safe='')}/forecasts/{quote(str(forecast_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_capacityplanning_longtermrequirements_automaticbestmethod_week_forecast_forceregenerate(self, business_unit_id, forecast_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplanning/longtermrequirements/automaticbestmethod/weeks/{quote(str(week_date_id), safe='')}/forecasts/{quote(str(forecast_id), safe='')}/forceregenerate", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_capacityplans(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans", params=params, **kwargs)

    def post_workforcemanagement_businessunit_capacityplans(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_capacityplans_bulk_remove(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/bulk/remove", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_capacityplan(self, business_unit_id, capacity_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_capacityplan(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_capacityplan_copy(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/copy", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_capacityplan_forecast(self, business_unit_id, capacity_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/forecast", params=params, **kwargs)

    def post_workforcemanagement_businessunit_capacityplan_requirement_generate(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/requirement/generate", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_capacityplan_staffinggroupallocations(self, business_unit_id, capacity_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/staffinggroupallocations", params=params, **kwargs)

    def post_workforcemanagement_businessunit_capacityplan_staffinggroupallocations(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/staffinggroupallocations", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_capacityplan_staffinggroupallocationshistory(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/staffinggroupallocationshistory", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_capacityplan_staffinggroupallocationshistory_query(self, business_unit_id, capacity_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/staffinggroupallocationshistory/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_capacityplan_staffingrequirements(self, business_unit_id, capacity_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/capacityplans/{quote(str(capacity_plan_id), safe='')}/staffingrequirements", params=params, **kwargs)

    def get_workforcemanagement_businessunit_decisionmetrics_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/decisionmetrics/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_decisionmetrics_update(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/decisionmetrics/update", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_decisionmetrics_update_uploadurl(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/decisionmetrics/update/uploadurl", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_intraday(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/intraday", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_intraday_planninggroups(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/intraday/planninggroups", params=params, **kwargs)

    def post_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_forecast_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/forecast/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_forecast_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/forecast/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_historical_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/historical/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_historical_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/historical/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_snapshot_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/snapshot/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_mainforecast_continuousforecast_session_export_snapshot_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/mainforecast/continuousforecast/session/export/snapshot/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_managementunits(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/managementunits", params=params, **kwargs)

    def get_workforcemanagement_businessunit_minimumstaffing_settings(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/minimumstaffing/settings", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_minimumstaffing_settings(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/minimumstaffing/settings", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_bulk_add(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/bulk/add", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_bulk_publish(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/bulk/publish", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_bulk_remove(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/bulk/remove", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_bulk_statuses_update(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/bulk/statuses/update", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_enrollments_bulk_statuses_update(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/enrollments/bulk/statuses/update", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_enrollments_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/enrollments/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_externalactivities_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/externalactivities/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_opportunities_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_opportunity(self, business_unit_id, opportunity_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/{quote(str(opportunity_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_opportunity(self, business_unit_id, opportunity_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/opportunities/{quote(str(opportunity_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_planninggroups(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/planninggroups", params=params, **kwargs)

    def post_workforcemanagement_businessunit_planninggroups(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/planninggroups", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_planninggroup(self, business_unit_id, planning_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/planninggroups/{quote(str(planning_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_planninggroup(self, business_unit_id, planning_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/planninggroups/{quote(str(planning_group_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_planninggroup(self, business_unit_id, planning_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/planninggroups/{quote(str(planning_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_schedulebids(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids", params=params, **kwargs)

    def post_workforcemanagement_businessunit_schedulebids(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_schedulebids_effectiveschedulesets(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/effectiveschedulesets", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_schedulebid(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_schedulebid(self, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_schedulebid(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_schedulebid_copy(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/copy", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_schedulebid_groups(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_schedulebid_groups_summary(self, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/summary", params=params, **kwargs)

    def delete_workforcemanagement_businessunit_schedulebid_group(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_schedulebid_group(self, bid_group_id, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_schedulebid_group(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_schedulebid_group_preferences(self, bid_group_id, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}/preferences", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_schedulebid_group_preferences(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/schedulebids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}/preferences", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_scheduler_settings(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduler/settings", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_scheduler_settings(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduler/settings", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_scheduling_runs(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduling/runs", params=params, **kwargs)

    def delete_workforcemanagement_businessunit_scheduling_run(self, business_unit_id, run_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduling/runs/{quote(str(run_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_scheduling_run(self, business_unit_id, run_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduling/runs/{quote(str(run_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_scheduling_run(self, business_unit_id, run_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduling/runs/{quote(str(run_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_scheduling_run_result(self, business_unit_id, run_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/scheduling/runs/{quote(str(run_id), safe='')}/result", params=params, **kwargs)

    def get_workforcemanagement_businessunit_servicegoaltemplates(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/servicegoaltemplates", params=params, **kwargs)

    def post_workforcemanagement_businessunit_servicegoaltemplates(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/servicegoaltemplates", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_servicegoaltemplate(self, business_unit_id, service_goal_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/servicegoaltemplates/{quote(str(service_goal_template_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_servicegoaltemplate(self, business_unit_id, service_goal_template_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/servicegoaltemplates/{quote(str(service_goal_template_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_servicegoaltemplate(self, business_unit_id, service_goal_template_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/servicegoaltemplates/{quote(str(service_goal_template_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_shifttrading_trades_evaluate_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/evaluate/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_shifttrading_trades_evaluate_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/evaluate/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_shifttrading_trades_query_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/query/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_shifttrading_trades_query_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_shifttrading_trades_state_bulk_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/state/bulk/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_shifttrading_trades_state_bulk_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/trades/state/bulk/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_shifttrading_unmatched_search_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/unmatched/search/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_shifttrading_unmatched_search_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/unmatched/search/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_shifttrading_weeks_summary_jobs(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/weeks/summary/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_shifttrading_weeks_summary_job(self, business_unit_id, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/shifttrading/weeks/summary/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_staffinggroups(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups", params=params, **kwargs)

    def post_workforcemanagement_businessunit_staffinggroups(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_staffinggroups_planninggroups_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups/planninggroups/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_staffinggroups_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups/query", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_staffinggroup(self, business_unit_id, staffing_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups/{quote(str(staffing_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_staffinggroup(self, business_unit_id, staffing_group_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups/{quote(str(staffing_group_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_staffinggroup(self, business_unit_id, staffing_group_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/staffinggroups/{quote(str(staffing_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_timeofflimits(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits", params=params, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimits(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimits_values_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/values/query", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_timeofflimit(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_timeofflimit(self, business_unit_id, time_off_limit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimit_granularityconversion(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/granularityconversion", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_timeofflimit_granularityconversion_jobs(self, business_unit_id, time_off_limit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/granularityconversion/jobs", params=params, **kwargs)

    def get_workforcemanagement_businessunit_timeofflimit_granularityconversion_job(self, business_unit_id, job_id, time_off_limit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/granularityconversion/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def put_workforcemanagement_businessunit_timeofflimit_values(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/values", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimit_values_import(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/values/import", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimit_values_import_uploadurl(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/values/import/uploadurl", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_timeofflimit_values_query(self, business_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/values/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_timeoffplans(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeoffplans", params=params, **kwargs)

    def post_workforcemanagement_businessunit_timeoffplans(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeoffplans", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_timeoffplan(self, business_unit_id, time_off_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_timeoffplan(self, business_unit_id, time_off_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_timeoffplan(self, business_unit_id, time_off_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_unavailabletimes_schedules_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/unavailabletimes/schedules/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_unavailabletimes_settings_query(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/unavailabletimes/settings/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_users(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/users", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecasts(self, business_unit_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_shorttermforecasts_generate(self, business_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/generate", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_shorttermforecasts_import(self, business_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/import", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_shorttermforecasts_import_uploadurl(self, business_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/import/uploadurl", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_week_shorttermforecast(self, business_unit_id, forecast_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_shorttermforecast_copy(self, business_unit_id, forecast_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/copy", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast_data(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/data", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast_generationresults(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/generationresults", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast_longtermforecastdata(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/longtermforecastdata", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast_planninggroups(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/planninggroups", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_shorttermforecast_staffingrequirement(self, business_unit_id, forecast_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shorttermforecasts/{quote(str(forecast_id), safe='')}/staffingrequirement", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_schedules(self, business_unit_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_schedules(self, business_unit_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedules_generate(self, business_unit_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/generate", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedules_import(self, business_unit_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/import", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedules_import_uploadurl(self, business_unit_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/import/uploadurl", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_week_schedule(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule(self, business_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_agentschedules_query(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/agentschedules/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_copy(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/copy", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule_generationresults(self, business_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/generationresults", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule_headcountforecast(self, business_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/headcountforecast", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule_history_agent(self, agent_id, business_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/history/agents/{quote(str(agent_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule_performancepredictions(self, business_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/performancepredictions", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_performancepredictions_recalculations(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/performancepredictions/recalculations", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_performancepredictions_recalculations_uploadurl(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/performancepredictions/recalculations/uploadurl", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_week_schedule_performancepredictions_recalculation(self, business_unit_id, recalculation_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/performancepredictions/recalculations/{quote(str(recalculation_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_reschedule(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/reschedule", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_update(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/update", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_week_schedule_update_uploadurl(self, business_unit_id, schedule_id, week_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}/update/uploadurl", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_workplanbids(self, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids", params=params, **kwargs)

    def post_workforcemanagement_businessunit_workplanbids(self, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids", params=params, body=body, **kwargs)

    def delete_workforcemanagement_businessunit_workplanbid(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_workplanbid(self, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_workplanbid(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_workplanbid_copy(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/copy", params=params, body=body, **kwargs)

    def post_workforcemanagement_businessunit_workplanbid_groups(self, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_workplanbid_groups_summary(self, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/summary", params=params, **kwargs)

    def delete_workforcemanagement_businessunit_workplanbid_group(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_workplanbid_group(self, bid_group_id, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_workplanbid_group(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_businessunit_workplanbid_group_preferences(self, bid_group_id, bid_id, business_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}/preferences", params=params, **kwargs)

    def patch_workforcemanagement_businessunit_workplanbid_group_preferences(self, bid_group_id, bid_id, business_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/businessunits/{quote(str(business_unit_id), safe='')}/workplanbids/{quote(str(bid_id), safe='')}/groups/{quote(str(bid_group_id), safe='')}/preferences", params=params, body=body, **kwargs)

    def get_workforcemanagement_calendar_data_ics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/calendar/data/ics', params=params, **kwargs)

    def delete_workforcemanagement_calendar_url_ics(self, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', '/api/v2/workforcemanagement/calendar/url/ics', params=params, body=body, **kwargs)

    def get_workforcemanagement_calendar_url_ics(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/calendar/url/ics', params=params, **kwargs)

    def post_workforcemanagement_calendar_url_ics(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/calendar/url/ics', params=params, body=body, **kwargs)

    def get_workforcemanagement_historicaldata_bulk_remove_jobs(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/historicaldata/bulk/remove/jobs', params=params, **kwargs)

    def post_workforcemanagement_historicaldata_bulk_remove_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/historicaldata/bulk/remove/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_historicaldata_bulk_remove_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/historicaldata/bulk/remove/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_historicaldata_importstatus(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/historicaldata/importstatus', params=params, **kwargs)

    def get_workforcemanagement_historicaldata_importstatus_job_id(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/historicaldata/importstatus/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_historicaldata_validate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/historicaldata/validate', params=params, body=body, **kwargs)

    def get_workforcemanagement_integrations_hris(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/integrations/hris', params=params, **kwargs)

    def get_workforcemanagement_integrations_hris_timeofftypes_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/integrations/hris/timeofftypes/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_integrations_hri_timeofftypes_jobs(self, hris_integration_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/integrations/hris/{quote(str(hris_integration_id), safe='')}/timeofftypes/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunits(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/managementunits', params=params, **kwargs)

    def post_workforcemanagement_managementunits(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/managementunits', params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunits_divisionviews(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/managementunits/divisionviews', params=params, **kwargs)

    def delete_workforcemanagement_managementunit(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_activitycodes(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/activitycodes", params=params, **kwargs)

    def get_workforcemanagement_managementunit_adherence(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/adherence", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_agents(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agents", params=params, body=body, **kwargs)

    def patch_workforcemanagement_managementunit_agents_workplans_bulk(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agents/workplans/bulk", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_agents_workplans_query(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agents/workplans/query", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_agent(self, agent_id, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agents/{quote(str(agent_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_managementunit_agent_shifttrades(self, agent_id, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agents/{quote(str(agent_id), safe='')}/shifttrades", params=params, **kwargs)

    def post_workforcemanagement_managementunit_agentschedules_search(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/agentschedules/search", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_decisionmetrics(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/decisionmetrics", params=params, **kwargs)

    def post_workforcemanagement_managementunit_historicaladherencequery(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/historicaladherencequery", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_move(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/move", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_schedules_search(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/schedules/search", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_selfschedule_settings(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/selfschedule/settings", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_selfschedule_settings(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/selfschedule/settings", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_shifttrades_matched(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/shifttrades/matched", params=params, **kwargs)

    def get_workforcemanagement_managementunit_shifttrades_users(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/shifttrades/users", params=params, **kwargs)

    def post_workforcemanagement_managementunit_shrinkage_jobs(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/shrinkage/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_timeofflimits(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits", params=params, **kwargs)

    def post_workforcemanagement_managementunit_timeofflimits(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_timeofflimits_values_query(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits/values/query", params=params, body=body, **kwargs)

    def delete_workforcemanagement_managementunit_timeofflimit(self, management_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_timeofflimit(self, management_unit_id, time_off_limit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_timeofflimit(self, management_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}", params=params, body=body, **kwargs)

    def put_workforcemanagement_managementunit_timeofflimit_values(self, management_unit_id, time_off_limit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeofflimits/{quote(str(time_off_limit_id), safe='')}/values", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_timeoffplans(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffplans", params=params, **kwargs)

    def post_workforcemanagement_managementunit_timeoffplans(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffplans", params=params, body=body, **kwargs)

    def delete_workforcemanagement_managementunit_timeoffplan(self, management_unit_id, time_off_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_timeoffplan(self, management_unit_id, time_off_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_timeoffplan(self, management_unit_id, time_off_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffplans/{quote(str(time_off_plan_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_timeoffrequests(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffrequests", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_timeoffrequests_integrationstatus_query(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffrequests/integrationstatus/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_timeoffrequests_query(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffrequests/query", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_timeoffrequests_waitlistpositions_query(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffrequests/waitlistpositions/query", params=params, body=body, **kwargs)

    def patch_workforcemanagement_managementunit_timeoffrequest_user_integrationstatus(self, management_unit_id, time_off_request_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/timeoffrequests/{quote(str(time_off_request_id), safe='')}/users/{quote(str(user_id), safe='')}/integrationstatus", params=params, body=body, **kwargs)

    def patch_workforcemanagement_managementunit_unavailabletimes_settings(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/unavailabletimes/settings", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_users(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users", params=params, **kwargs)

    def post_workforcemanagement_managementunit_user_timeoffbalance_jobs(self, management_unit_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffbalance/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_user_timeoffrequests(self, management_unit_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests", params=params, **kwargs)

    def post_workforcemanagement_managementunit_user_timeoffrequests_estimate(self, management_unit_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests/estimate", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_user_timeoffrequest(self, management_unit_id, time_off_request_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests/{quote(str(time_off_request_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_user_timeoffrequest(self, management_unit_id, time_off_request_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests/{quote(str(time_off_request_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_user_timeoffrequest_timeoffbalance_jobs(self, management_unit_id, time_off_request_id, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests/{quote(str(time_off_request_id), safe='')}/timeoffbalance/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_user_timeoffrequest_timeofflimits(self, management_unit_id, time_off_request_id, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/users/{quote(str(user_id), safe='')}/timeoffrequests/{quote(str(time_off_request_id), safe='')}/timeofflimits", params=params, **kwargs)

    def get_workforcemanagement_managementunit_week_shifttrades(self, management_unit_id, week_date_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades", params=params, **kwargs)

    def post_workforcemanagement_managementunit_week_shifttrades(self, management_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_week_shifttrades_search(self, management_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades/search", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_week_shifttrades_state_bulk(self, management_unit_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades/state/bulk", params=params, body=body, **kwargs)

    def patch_workforcemanagement_managementunit_week_shifttrade(self, management_unit_id, trade_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades/{quote(str(trade_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_week_shifttrade_match(self, management_unit_id, trade_id, week_date_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_date_id), safe='')}/shifttrades/{quote(str(trade_id), safe='')}/match", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_week_schedules(self, management_unit_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules", params=params, **kwargs)

    def get_workforcemanagement_managementunit_week_schedule(self, management_unit_id, schedule_id, week_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/weeks/{quote(str(week_id), safe='')}/schedules/{quote(str(schedule_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_managementunit_workplanrotations(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations", params=params, **kwargs)

    def post_workforcemanagement_managementunit_workplanrotations(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations", params=params, body=body, **kwargs)

    def delete_workforcemanagement_managementunit_workplanrotation(self, management_unit_id, work_plan_rotation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations/{quote(str(work_plan_rotation_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_workplanrotation(self, management_unit_id, work_plan_rotation_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations/{quote(str(work_plan_rotation_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_workplanrotation(self, management_unit_id, work_plan_rotation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations/{quote(str(work_plan_rotation_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_workplanrotation_copy(self, management_unit_id, work_plan_rotation_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplanrotations/{quote(str(work_plan_rotation_id), safe='')}/copy", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_workplans(self, management_unit_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans", params=params, **kwargs)

    def post_workforcemanagement_managementunit_workplans(self, management_unit_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans", params=params, body=body, **kwargs)

    def delete_workforcemanagement_managementunit_workplan(self, management_unit_id, work_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('DELETE', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans/{quote(str(work_plan_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_managementunit_workplan(self, management_unit_id, work_plan_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans/{quote(str(work_plan_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_managementunit_workplan(self, management_unit_id, work_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans/{quote(str(work_plan_id), safe='')}", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_workplan_copy(self, management_unit_id, work_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans/{quote(str(work_plan_id), safe='')}/copy", params=params, body=body, **kwargs)

    def post_workforcemanagement_managementunit_workplan_validate(self, management_unit_id, work_plan_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/managementunits/{quote(str(management_unit_id), safe='')}/workplans/{quote(str(work_plan_id), safe='')}/validate", params=params, body=body, **kwargs)

    def get_workforcemanagement_notifications(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/notifications', params=params, **kwargs)

    def post_workforcemanagement_notifications_update(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/notifications/update', params=params, body=body, **kwargs)

    def get_workforcemanagement_schedulebids(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/schedulebids', params=params, **kwargs)

    def get_workforcemanagement_schedulebid_preference(self, bid_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/schedulebids/{quote(str(bid_id), safe='')}/preference", params=params, **kwargs)

    def put_workforcemanagement_schedulebid_preference(self, bid_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PUT', f"/api/v2/workforcemanagement/schedulebids/{quote(str(bid_id), safe='')}/preference", params=params, body=body, **kwargs)

    def get_workforcemanagement_schedulebid_schedulesets(self, bid_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/schedulebids/{quote(str(bid_id), safe='')}/schedulesets", params=params, **kwargs)

    def post_workforcemanagement_schedules(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/schedules', params=params, body=body, **kwargs)

    def get_workforcemanagement_schedulingjob(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/schedulingjobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_selfschedule_activitymove(self, activity_move_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/selfschedule/activitymoves/{quote(str(activity_move_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_selfschedule_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/selfschedule/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_selfschedule_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/selfschedule/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_selfschedule_offers_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/selfschedule/offers/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_selfschedule_offers_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/selfschedule/offers/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_selfschedule_query(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/selfschedule/query', params=params, **kwargs)

    def get_workforcemanagement_selfschedule_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/selfschedule/settings', params=params, **kwargs)

    def get_workforcemanagement_shifttrades(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/shifttrades', params=params, **kwargs)

    def post_workforcemanagement_shifttrading_trades_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/shifttrading/trades/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_shifttrading_trades_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shifttrading/trades/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_shifttrading_trades_mine_query_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/shifttrading/trades/mine/query/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_shifttrading_trades_mine_query_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shifttrading/trades/mine/query/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_shifttrading_trade_jobs(self, trade_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_shifttrading_trade_job(self, job_id, trade_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_shifttrading_trade_match_jobs(self, trade_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/match/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_shifttrading_trade_match_job(self, job_id, trade_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/match/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_shifttrading_trade_state_jobs(self, trade_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/state/jobs", params=params, body=body, **kwargs)

    def get_workforcemanagement_shifttrading_trade_state_job(self, job_id, trade_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shifttrading/trades/{quote(str(trade_id), safe='')}/state/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_shrinkage_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/shrinkage/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def get_workforcemanagement_team_adherence(self, team_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/teams/{quote(str(team_id), safe='')}/adherence", params=params, **kwargs)

    def post_workforcemanagement_team_adherence_historical(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/teams/{quote(str(team_id), safe='')}/adherence/historical", params=params, body=body, **kwargs)

    def post_workforcemanagement_team_shrinkage_jobs(self, team_id, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', f"/api/v2/workforcemanagement/teams/{quote(str(team_id), safe='')}/shrinkage/jobs", params=params, body=body, **kwargs)

    def post_workforcemanagement_timeoffbalance_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/timeoffbalance/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_timeoffbalance_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/timeoffbalance/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_timeofflimits_available_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/timeofflimits/available/query', params=params, body=body, **kwargs)

    def get_workforcemanagement_timeoffrequests(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/timeoffrequests', params=params, **kwargs)

    def post_workforcemanagement_timeoffrequests(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/timeoffrequests', params=params, body=body, **kwargs)

    def post_workforcemanagement_timeoffrequests_estimate(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/timeoffrequests/estimate', params=params, body=body, **kwargs)

    def post_workforcemanagement_timeoffrequests_integrationstatus_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/timeoffrequests/integrationstatus/query', params=params, body=body, **kwargs)

    def get_workforcemanagement_timeoffrequest(self, time_off_request_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/timeoffrequests/{quote(str(time_off_request_id), safe='')}", params=params, **kwargs)

    def patch_workforcemanagement_timeoffrequest(self, time_off_request_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/timeoffrequests/{quote(str(time_off_request_id), safe='')}", params=params, body=body, **kwargs)

    def get_workforcemanagement_timeoffrequest_waitlistpositions(self, time_off_request_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/timeoffrequests/{quote(str(time_off_request_id), safe='')}/waitlistpositions", params=params, **kwargs)

    def patch_workforcemanagement_unavailabletimes(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/workforcemanagement/unavailabletimes', params=params, body=body, **kwargs)

    def post_workforcemanagement_unavailabletimes_query(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/unavailabletimes/query', params=params, body=body, **kwargs)

    def get_workforcemanagement_unavailabletimes_settings(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/unavailabletimes/settings', params=params, **kwargs)

    def post_workforcemanagement_unavailabletimes_validation_jobs(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/unavailabletimes/validation/jobs', params=params, body=body, **kwargs)

    def get_workforcemanagement_unavailabletimes_validation_job(self, job_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/unavailabletimes/validation/jobs/{quote(str(job_id), safe='')}", params=params, **kwargs)

    def post_workforcemanagement_users_activity(self, body=None, params=None, **kwargs):
        return self._request_platform_api('POST', '/api/v2/workforcemanagement/users/activity', params=params, body=body, **kwargs)

    def patch_workforcemanagement_users_workplanbidranks_bulk(self, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', '/api/v2/workforcemanagement/users/workplanbidranks/bulk', params=params, body=body, **kwargs)

    def get_workforcemanagement_user_workplanbidranks(self, user_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/users/{quote(str(user_id), safe='')}/workplanbidranks", params=params, **kwargs)

    def patch_workforcemanagement_user_workplanbidranks(self, user_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/users/{quote(str(user_id), safe='')}/workplanbidranks", params=params, body=body, **kwargs)

    def get_workforcemanagement_workplanbids(self, params=None, **kwargs):
        return self._request_platform_api('GET', '/api/v2/workforcemanagement/workplanbids', params=params, **kwargs)

    def get_workforcemanagement_workplanbid_preferences(self, bid_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/workplanbids/{quote(str(bid_id), safe='')}/preferences", params=params, **kwargs)

    def patch_workforcemanagement_workplanbid_preferences(self, bid_id, body=None, params=None, **kwargs):
        return self._request_platform_api('PATCH', f"/api/v2/workforcemanagement/workplanbids/{quote(str(bid_id), safe='')}/preferences", params=params, body=body, **kwargs)

    def get_workforcemanagement_workplanbid_workplans(self, bid_id, params=None, **kwargs):
        return self._request_platform_api('GET', f"/api/v2/workforcemanagement/workplanbids/{quote(str(bid_id), safe='')}/workplans", params=params, **kwargs)

