import type { IAuthenticateGeneric, ICredentialTestRequest, ICredentialType, INodeProperties, Icon } from 'n8n-workflow';

export class AgentForgeGuardApi implements ICredentialType {
  name = 'agentForgeGuardApi';
  displayName = 'AgentForge Guard API';
  icon: Icon = { light: 'file:../nodes/AgentForgeGuard/agentforge-guard.svg', dark: 'file:../nodes/AgentForgeGuard/agentforge-guard.dark.svg' };
  documentationUrl = 'https://github.com/dennislee928/AgentForge-Guard/blob/main/docs/n8n-api.md';
  properties: INodeProperties[] = [
    { displayName: 'Base URL', name: 'baseUrl', type: 'string', default: 'http://127.0.0.1:8787', required: true, description: 'Gateway URL. Use HTTPS for remote services; HTTP is supported only on loopback.' },
    { displayName: 'API Key', name: 'apiKey', type: 'string', typeOptions: { password: true }, default: '', required: true },
  ];
  authenticate: IAuthenticateGeneric = {
    type: 'generic',
    properties: { headers: { Authorization: '=Bearer {{$credentials.apiKey}}' } },
  };
  test: ICredentialTestRequest = {
    request: { baseURL: '={{$credentials.baseUrl}}', url: '/v1/health', method: 'GET' },
  };
}
