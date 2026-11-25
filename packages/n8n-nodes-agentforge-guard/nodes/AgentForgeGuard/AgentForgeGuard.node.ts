import type { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import { checkedEvaluation, gatewayUrl, parseArgv } from './contract';

export class AgentForgeGuard implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'AgentForge Guard',
    name: 'agentForgeGuard',
    icon: { light: 'file:agentforge-guard.svg', dark: 'file:agentforge-guard.dark.svg' },
    group: ['transform'],
    version: 1,
    usableAsTool: true,
    subtitle: '={{$parameter["resource"] + ": " + $parameter["operation"]}}',
    description: 'Evaluate AI agent commands with the AgentForge Guard policy engine',
    defaults: { name: 'AgentForge Guard' },
    inputs: [NodeConnectionTypes.Main],
    outputs: [NodeConnectionTypes.Main],
    credentials: [{ name: 'agentForgeGuardApi', required: true }],
    properties: [
      {
        displayName: 'Resource', name: 'resource', type: 'options', noDataExpression: true, default: 'policy',
        options: [{ name: 'Command', value: 'command' }, { name: 'Policy', value: 'policy' }, { name: 'Security', value: 'security' }],
      },
      {
        displayName: 'Operation', name: 'operation', type: 'options', noDataExpression: true, displayOptions: { show: { resource: ['policy'] } }, default: 'evaluate',
        options: [{ name: 'Evaluate', value: 'evaluate', description: 'Evaluate a structured command against the gateway policy', action: 'Evaluate a policy' }],
      },
      {
        displayName: 'Operation', name: 'operation', type: 'options', noDataExpression: true, displayOptions: { show: { resource: ['command'] } }, default: 'analyze',
        options: [{ name: 'Analyze', value: 'analyze', description: 'Analyze deterministic policy reasons for a command', action: 'Analyze a command' }],
      },
      {
        displayName: 'Operation', name: 'operation', type: 'options', noDataExpression: true, displayOptions: { show: { resource: ['security'] } }, default: 'validate',
        options: [{ name: 'Validate', value: 'validate', description: 'Stop the workflow unless the engine returns allow', action: 'Validate security' }],
      },
      { displayName: 'Argv', name: 'argv', type: 'json', default: '["git", "status"]', required: true, description: 'Structured command arguments as a JSON array of strings. The gateway evaluates them without executing.' },
      {
        displayName: 'Requested Backend', name: 'requestedBackend', type: 'options', default: 'policy',
        description: 'Ask the engine for stronger isolation. The engine never weakens policy requirements.',
        options: [{ name: 'Policy Default', value: 'policy' }, { name: 'Container', value: 'container' }, { name: 'Local', value: 'local' }],
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const output: INodeExecutionData[] = [];
    for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
      let validationFailure = false;
      try {
        const resource = this.getNodeParameter('resource', itemIndex) as string;
        const operation = this.getNodeParameter('operation', itemIndex) as string;
        if (!['policy:evaluate', 'command:analyze', 'security:validate'].includes(`${resource}:${operation}`)) {
          throw new NodeOperationError(this.getNode(), 'Unsupported operation', { itemIndex });
        }
        const argv = parseArgv(this.getNodeParameter('argv', itemIndex));
        const requestedBackend = this.getNodeParameter('requestedBackend', itemIndex) as string;
        if (!['policy', 'local', 'container'].includes(requestedBackend)) throw new NodeOperationError(this.getNode(), 'Invalid backend', { itemIndex });
        const credentials = await this.getCredentials('agentForgeGuardApi');
        const url = `${gatewayUrl(credentials.baseUrl)}/v1/evaluate`;
        const response: unknown = await this.helpers.httpRequestWithAuthentication.call(this, 'agentForgeGuardApi', {
          method: 'POST', url,
          body: { argv, ...(requestedBackend === 'policy' ? {} : { requestedBackend }) },
          json: true, timeout: 10000, disableFollowRedirect: true,
        });
        const decision = checkedEvaluation(response);
        if (resource === 'security' && decision.effect !== 'allow') {
          validationFailure = true;
          throw new NodeOperationError(this.getNode(), 'Security validation did not return allow', { itemIndex });
        }
        output.push({ json: decision, pairedItem: { item: itemIndex } });
      } catch {
        // HTTP errors can contain credentials, headers and request bodies. Never surface them.
        const message = validationFailure ? 'Security validation stopped: the policy did not allow this command' :
          'AgentForge Guard request failed; no decision was accepted';
        if (this.continueOnFail()) {
          output.push({ json: { error: message }, pairedItem: { item: itemIndex } });
        } else {
          throw new NodeOperationError(this.getNode(), message, { itemIndex });
        }
      }
    }
    return [output];
  }
}
