import requests
import os
import json
from dotenv import load_dotenv
import PureCloudPlatformClientV2
from PureCloudPlatformClientV2.rest import ApiException
import time

load_dotenv()

class Genesys:
    DADOS = json.loads(os.environ.get('DADOS'))

    def __init__(self, org: str) -> None:
        if org not in self.DADOS.keys():
            raise ValueError('Organização Desconhecida')
        self.URL = self.DADOS[org]['URL']
        self.CLIENT_ID = self.DADOS[org]['CLIENT_ID']
        self.CLIENT_SECRET = self.DADOS[org]['CLIENT_SECRET']
        self._call_count = 0
        self._last_reset_time = time.time()
        self._update_apis()
        
    def _update_apis(self):
        self.client_api = PureCloudPlatformClientV2.api_client.ApiClient(host=self.URL).get_client_credentials_token(self.CLIENT_ID, self.CLIENT_SECRET)
        self.architect_api = PureCloudPlatformClientV2.ArchitectApi(self.client_api)
        self.conversation_api = PureCloudPlatformClientV2.ConversationsApi(self.client_api)
        self.telephony_providers_edge_api = PureCloudPlatformClientV2.TelephonyProvidersEdgeApi(self.client_api)
        self.integrations_api = PureCloudPlatformClientV2.IntegrationsApi(self.client_api)
        self.objects_api = PureCloudPlatformClientV2.ObjectsApi(self.client_api)
        
    def _check_and_update_apiclient(self):
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
    
    def get_authorization_divisions(self, page_size: int = 25, page_number: int = 1, sort_by: str = None, expand: list = None, next_page: str = None, previous_page: str = None, object_count: bool = False, id: list = None, name: str = None) -> PureCloudPlatformClientV2.AuthzDivisionEntityListing:
        """
        Retrieve a list of all divisions defined for the organization.

        Wraps GET /api/v2/authorization/divisions

        Requires no permissions
        """
        try:
            # Retrieve a list of all divisions defined for the organization
            return self.objects_api.get_authorization_divisions(page_size=page_size, page_number=page_number, sort_by=sort_by, expand=expand, next_page=next_page, previous_page=previous_page, object_count=object_count, id=id, name=name)
        except Exception as error:
            raise Exception(f'Falha na chamada(get_authorization_divisions({page_size=}, {page_number=}, {sort_by=}, {expand=}, {next_page=}, {previous_page=}, {object_count=}, {id=}, {name=}))\n{error=}')

    def get_conversations_call(self, conversation_id: str) -> PureCloudPlatformClientV2.CallConversation:
        """
        Get call conversation

        Wraps GET /api/v2/conversations/calls/{conversationId}

        Requires no permissions 
        """
        try:
            self._check_and_update_apiclient()
            return self.conversation_api.get_conversations_call(conversation_id)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_conversations_call({conversation_id=}))\n{error=}')

    def get_architect_prompts(self, page_number: int = 1, page_size: int = 25, name: list = [''], description: str = '', name_or_description: str = '', sort_by: str = 'id', sort_order: str = 'asc', include_media_uris: bool = True, include_resources: bool = True, language: list = ['']) -> PureCloudPlatformClientV2.PromptEntityListing:
        """
        Get a pageable list of user prompts

        The returned list is pageable, and query parameters can be used for filtering. Multiple names can be specified, in which case all matching prompts will be returned, and no other filters will be evaluated.

        Wraps GET /api/v2/architect/prompts

        Requires ALL permissions:

        architect:userPrompt:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_architect_prompts(page_number=page_number, page_size=page_size, name=name, description=description, name_or_description=name_or_description, sort_by=sort_by, sort_order=sort_order, include_media_uris=include_media_uris, include_resources=include_resources, language=language)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_architect_prompts({page_number=}, {page_size=}, {name=}, {description=}, {name_or_description=}, {sort_by=}, {sort_order=}, {include_media_uris=}, {include_resources=}, {language=}))\n{error=}')

    def get_architect_systemprompts(self, page_number: int = 1, page_size: int = 25, sort_by: str = 'id', sort_order: str = 'asc', name: str = '', description: str = '', name_or_description: str = '', include_media_uris: bool = True, include_resources: bool = True, language: list = ['']) -> PureCloudPlatformClientV2.SystemPromptEntityListing:
        """
        Get System Prompts

        Wraps GET /api/v2/architect/systemprompts

        Requires ALL permissions:

        architect:systemPrompt:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_architect_systemprompts(page_number=page_number, page_size=page_size, sort_by=sort_by, sort_order=sort_order, name=name, description=description, name_or_description=name_or_description, include_media_uris=include_media_uris, include_resources=include_resources, language=language)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_architect_systemprompts({page_number=}, {page_size=}, {sort_by=}, {sort_order=}, {name=}, {description=}, {name_or_description=}, {include_media_uris=}, {include_resources=}, {language=}))\n{error=}')
    
    def get_flows_datatable_row(self, datatable_id: str, row_id: str, showbrief: bool = False) -> dict[str, object]:
        """
        Returns a specific row for the datatable

        Given a datatableId and a rowId (the value of the key field) this will return the full row contents for that rowId.

        Wraps GET /api/v2/flows/datatables/{datatableId}/rows/{rowId}

        Requires ANY permissions:

        architect:datatable:view
        architect:datatableRow:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_flows_datatable_row(datatable_id, row_id, showbrief=showbrief)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_flows_datatable_row({datatable_id=}, {row_id=}, {showbrief=}))\n{error=}')
    
    def get_flows_datatables(self, expand: str = '', page_number: int = 1, page_size: int = 25, sort_by: str = 'id', sort_order: str = 'asc', division_id: list[str] = [''], name: str = '') -> PureCloudPlatformClientV2.DataTablesDomainEntityListing:
        """
        Retrieve a list of datatables for the org

        Wraps GET /api/v2/flows/datatables

        Requires ALL permissions:

        architect:datatable:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_flows_datatables(expand=expand, page_number=page_number, page_size=page_size, sort_by=sort_by, sort_order=sort_order, name=name)
        except Exception as error:
            raise Exception(f'Falha na chamada(get_flows_datatables({expand=}, {page_number=}, {page_size=}, {sort_by=}, {sort_order=}, {division_id=}, {name=}))\n{error=}')
    
    def get_integrations_actions(self, page_size: int = 25, page_number: int = 1, next_page: str = None, previous_page: str = None, sort_by: str = None, sort_order: str = 'asc', category: str = None, name: str = None, ids: str = None, secure: str = None, include_auth_actions: str = 'false') -> PureCloudPlatformClientV2.ActionEntityListing:
        """
        Retrieves all actions associated with filters passed in via query param.

        Wraps GET /api/v2/integrations/actions

        Requires ANY permissions:

        integrations:action:view
        bridge:actions:view
        """
        try:
            self._check_and_update_apiclient()
            return self.integrations_api.get_integrations_actions(page_size=page_size, page_number=page_number, next_page=next_page, previous_page=previous_page, sort_by=sort_by, sort_order=sort_order, category=category, name=name, ids=ids, secure=secure, include_auth_actions=include_auth_actions)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_integrations_actions({page_size=}, {page_number=}, {next_page=}, {previous_page=}, {sort_by=}, {sort_order=}, {category=}, {name=}, {ids=}, {secure=}, {include_auth_actions=}))\n{error=}')

    def post_integrations_action_test(self, action_id: str, body=None) -> PureCloudPlatformClientV2.TestExecutionResult:
        """
        Test the execution of an action. Responses will show execution steps broken out with intermediate results to help in debugging.

        Wraps POST /api/v2/integrations/actions/{actionId}/test

        Requires no permissions
        """
        try:
            # Test the execution of an action. Responses will show execution steps broken out with intermediate results to help in debugging.
            return self.integrations_api.post_integrations_action_test(action_id, body)
        except ApiException as error:
            raise Exception(f'Falha na chamada(post_integrations_action_test({action_id=}, {body=}))\n{error=}')

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

    def get_architect_ivr(self, ivr_id: str) -> PureCloudPlatformClientV2.IVR:
        """
        Get an IVR config.

        Wraps GET /api/v2/architect/ivrs/{ivrId}

        Requires ALL permissions:

        routing:callRoute:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_architect_ivr(ivr_id)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_architect_ivr({ivr_id=}))\n{error=}')
    
    def get_architect_ivrs(self, page_number: int = 1, page_size: int = 25, sort_by: str = '', sort_order: str = 'ASC', name: str = '', dnis: str = '', schedule_group: str = '') -> PureCloudPlatformClientV2.IVREntityListing:
        """
        Get IVR configs.

        Wraps GET /api/v2/architect/ivrs

        Requires ALL permissions:

        routing:callRoute:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_architect_ivrs(page_number=page_number, page_size=page_size, sort_by=sort_by, sort_order=sort_order, name=name, dnis=dnis, schedule_group=schedule_group)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_architect_ivrs({page_number=},{page_size=},{sort_by=},{sort_order=},{name=},{dnis=},{schedule_group=}))\n{error=}')

    def get_telephony_providers_edges_didpools_dids(self, type: str, id: list = [''], number_match: str = '', page_size: int = 25, page_number: int = 1, sort_order: str = 'ascending') -> PureCloudPlatformClientV2.DIDNumberEntityListing:
        """
        Get a listing of unassigned and/or assigned numbers in a set of DID Pools.

        Wraps GET /api/v2/telephony/providers/edges/didpools/dids

        Requires ALL permissions:

        telephony:did:view
        """
        try:
            self._check_and_update_apiclient()
            return self.telephony_providers_edge_api.get_telephony_providers_edges_didpools_dids(type, id=id, number_match=number_match, page_size=page_size, page_number=page_number, sort_order=sort_order)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_telephony_providers_edges_didpools_dids({type=},{id=},{number_match=},{page_size=},{page_number=},{sort_order=}))\n{error=}')

    def get_flows(self, type: list[str] = ['inboundcall'], page_number: int = 1, page_size: int = 25, sort_by: str = 'id', sort_order: str = 'asc', id: list[str] = [''], name: str = '', description: str = '', name_or_description: str = '', publish_version_id: str = '', editable_by: str = '', locked_by: str = '', locked_by_client_id: str = '', secure: str = '', deleted: bool = False, include_schemas: bool = False, published_after: str = '', published_before: str = '', division_id: list[str] = ['']) -> PureCloudPlatformClientV2.FlowEntityListing:
        """
        Get a pageable list of flows, filtered by query parameters

        If one or more IDs are specified, the search will fetch flows that match the given ID(s) and not use any additional supplied query parameters in the search.

        Wraps GET /api/v2/flows

        Requires ANY permissions:

        architect:flow:view
        """
        try:
            self._check_and_update_apiclient()
            return self.architect_api.get_flows(type=type, page_number=page_number, page_size=page_size, sort_by=sort_by, sort_order=sort_order, id=id, name=name, description=description, name_or_description=name_or_description, publish_version_id=publish_version_id, editable_by=editable_by, locked_by=locked_by, locked_by_client_id=locked_by_client_id, secure=secure, deleted=deleted, include_schemas=include_schemas, published_after=published_after, published_before=published_before, division_id=division_id)
        except ApiException as error:
            raise Exception(f'Falha na chamada(get_flows({type=}, {page_number=}, {page_size=}, {sort_by=}, {sort_order=}, {id=}, {name=}, {description=}, {name_or_description=}, {publish_version_id=}, {editable_by=}, {locked_by=}, {locked_by_client_id=}, {secure=}, {deleted=}, {include_schemas=}, {published_after=}, {published_before=}, {division_id=}))\n{error=}')
 
    def post_architect_prompts(self, name: str, description: str = '') -> PureCloudPlatformClientV2.Prompt:
        """
        Create a new user prompt

        Wraps POST /api/v2/architect/prompts

        Requires ALL permissions:

        architect:userPrompt:add
        """
        try:
            self._check_and_update_apiclient()
            prompt = PureCloudPlatformClientV2.Prompt()
            prompt.name = name
            prompt.description = description
            return self.architect_api.post_architect_prompts(prompt) 
        except ApiException as error:
            raise Exception(f'Falha na chamada(post_architect_prompts({name=}, {description=}))\n{error=}')
    
    def post_architect_prompt_resources(self, prompt_id: str, language: str, tts_string: str = '', text: str = '') -> PureCloudPlatformClientV2.PromptAsset:
        """
        Create a new user prompt resource

        Wraps POST /api/v2/architect/prompts/{promptId}/resources

        Requires ALL permissions:

        architect:userPrompt:edit
        """
        try:
            self._check_and_update_apiclient()
            prompt = PureCloudPlatformClientV2.PromptAssetCreate()
            prompt.language = language
            prompt.tts_string = tts_string
            prompt.text = text
            return self.architect_api.post_architect_prompt_resources(prompt_id, prompt)
        except ApiException as error:
            raise Exception(f'Falha na chamada(post_architect_prompt_resources({prompt_id=}, {language=}, {tts_string=}, {text=}))\n{error=}')
        
    def post_architect_prompt_upload(self, upload_url: str, file_name: str, file_path: str) -> dict:
        """
        Upload file a user prompt resource

        Wraps POST

        Requires ALL permissions:

        architect:userPrompt:edit
        """
        try:
            self._check_and_update_apiclient()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"bearer {self.client_api.access_token}"
            }
            wav_form_data = {
                'file': (file_name, open(file_path, 'rb'))
            }

            response = requests.post(upload_url, files=wav_form_data, headers=headers)
            if not response.ok:
                raise Exception(f'Falha na chamada(post_architect_prompt_upload({upload_url=}, {file_name=}, {file_path=}))\nFailure: {response.status_code} - {response.reason}')
            return response.json()
        except Exception as error:
            raise Exception(f'Falha na chamada(post_architect_prompt_upload({upload_url=}, {file_name=}, {file_path=}))\n{error=}')

if __name__ == '__main__':
    api = Genesys('MOVIDA')
    