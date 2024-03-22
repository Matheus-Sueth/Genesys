import requests
import os
import json
from dotenv import load_dotenv
import PureCloudPlatformClientV2

load_dotenv()


class Genesys:
    DADOS = json.loads(os.environ.get('DADOS'))

    def __init__(self, org: str) -> None:
        if org not in self.DADOS.keys():
            raise ValueError('Organização Desconhecida')
        self.URL = self.DADOS[org]['URL']
        self.URL = self.URL if 'https://' in self.URL else 'https://' + self.URL
        self.CLIENT_ID = self.DADOS[org]['CLIENT_ID']
        self.CLIENT_SECRET = self.DADOS[org]['CLIENT_SECRET']
        self._update_apis()

    def _update_apis(self):
        self.client_api = PureCloudPlatformClientV2.api_client.ApiClient(host=self.URL).get_client_credentials_token(self.CLIENT_ID, self.CLIENT_SECRET)
        self.architect_api = PureCloudPlatformClientV2.ArchitectApi(self.client_api)
        self.conversation_api = PureCloudPlatformClientV2.ConversationsApi(self.client_api)
        self.telephony_providers_edge_api = PureCloudPlatformClientV2.TelephonyProvidersEdgeApi(self.client_api)
        self.integrations_api = PureCloudPlatformClientV2.IntegrationsApi(self.client_api)
        self.objects_api = PureCloudPlatformClientV2.ObjectsApi(self.client_api)
        self.routing_api = PureCloudPlatformClientV2.RoutingApi(self.client_api)
                
    def __new__(self, *args):
        if not hasattr(self, 'instance'):
            self.instance = super(Genesys, self).__new__(self)
        return self.instance
       
    def post_architect_prompt_upload(self, upload_url: str, file_name: str, file_path: str) -> dict:
        """
        Upload file a user prompt resource

        Wraps POST

        Requires ALL permissions:

        architect:userPrompt:edit
        """
        try:
            headers = {
                "Authorization": f"bearer {self.client_api.access_token}"
            }
            wav_form_data = {
                'file': (file_name, open(file_path, 'rb'))
            }

            response = requests.post(upload_url, files=wav_form_data, headers=headers)
            if not response.ok:
                raise Exception(f'Failure: {response.status_code} - {response.reason}')
            return response.json()
        except Exception as error:
            raise Exception(f'Falha na chamada(post_architect_prompt_upload({upload_url=}, {file_name=}, {file_path=}))\n{error=}')
