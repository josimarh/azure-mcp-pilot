import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as vscode from 'vscode';

const run = promisify(execFile);

const PROVIDER_ID = 'idengraph.provider';
const SERVER_LABEL = 'IdenGraph';
const PACKAGE_NAME = 'idengraph';

/**
 * O servidor MCP é um pacote Python executado via `uvx`. A extensão não o
 * substitui: ela apenas o registra no VS Code e cuida da experiência de
 * pré-requisitos, para que uma máquina sem `uv` ou sem sessão do Azure CLI
 * receba uma orientação clara em vez de uma falha de processo.
 */
export function activate(context: vscode.ExtensionContext): void {
	const didChangeEmitter = new vscode.EventEmitter<void>();

	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration(event => {
			if (event.affectsConfiguration('idengraph')) {
				didChangeEmitter.fire();
			}
		})
	);

	context.subscriptions.push(
		vscode.lm.registerMcpServerDefinitionProvider(PROVIDER_ID, {
			onDidChangeMcpServerDefinitions: didChangeEmitter.event,

			provideMcpServerDefinitions: async () => {
				const config = vscode.workspace.getConfiguration('idengraph');

				const env: Record<string, string> = {
					MOCK_MODE: String(config.get<boolean>('useMockData', false)),
					SANITIZE_FOR_LLM: String(config.get<boolean>('sanitizeOutput', true))
				};

				const subscriptions = config.get<string>('subscriptions', '').trim();
				if (subscriptions) {
					env.AZURE_SUBSCRIPTIONS = subscriptions;
				}

				return [
					new vscode.McpStdioServerDefinition(
						SERVER_LABEL,
						'uvx',
						[PACKAGE_NAME],
						env,
						context.extension.packageJSON.version
					)
				];
			},

			resolveMcpServerDefinition: async (server: vscode.McpServerDefinition) => {
				const uvAvailable = await isCommandAvailable('uvx', ['--version']);
				if (!uvAvailable) {
					const install = 'Como instalar';
					const choice = await vscode.window.showErrorMessage(
						'IdenGraph precisa do `uv` para executar o servidor MCP, mas ele não foi encontrado no PATH.',
						install
					);
					if (choice === install) {
						vscode.env.openExternal(vscode.Uri.parse('https://docs.astral.sh/uv/getting-started/installation/'));
					}
					return undefined;
				}

				// Em modo mock não há consulta ao tenant, então a sessão do Azure
				// CLI é irrelevante e não deve bloquear o início do servidor.
				const usingMock = vscode.workspace.getConfiguration('idengraph').get<boolean>('useMockData', false);
				if (usingMock) {
					return server;
				}

				const signedIn = await isAzureSignedIn();
				if (!signedIn) {
					const howTo = 'Como entrar';
					const useMock = 'Usar dados fictícios';
					const choice = await vscode.window.showErrorMessage(
						'IdenGraph precisa de uma sessão ativa do Azure CLI. Execute `az login` em um terminal.',
						howTo,
						useMock
					);
					if (choice === howTo) {
						vscode.env.openExternal(
							vscode.Uri.parse('https://learn.microsoft.com/cli/azure/authenticate-azure-cli')
						);
					} else if (choice === useMock) {
						await vscode.workspace
							.getConfiguration('idengraph')
							.update('useMockData', true, vscode.ConfigurationTarget.Global);
					}
					return undefined;
				}

				return server;
			}
		})
	);
}

export function deactivate(): void {
	// Sem estado a liberar: o servidor MCP é gerenciado pelo VS Code.
}

async function isCommandAvailable(command: string, args: string[]): Promise<boolean> {
	try {
		await run(command, args, { timeout: 15_000, shell: true });
		return true;
	} catch {
		return false;
	}
}

/**
 * Verifica se há uma sessão utilizável do Azure CLI. `az account show` falha
 * tanto quando o CLI não está instalado quanto quando não há login ativo, e
 * ambos os casos exigem a mesma ação do usuário.
 */
async function isAzureSignedIn(): Promise<boolean> {
	try {
		const { stdout } = await run('az', ['account', 'show', '--output', 'json'], {
			timeout: 30_000,
			shell: true
		});
		const account = JSON.parse(stdout) as { id?: string };
		return Boolean(account.id);
	} catch {
		return false;
	}
}
