import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as vscode from 'vscode';

const run = promisify(execFile);

const PROVIDER_ID = 'idengraph.provider';
const SERVER_LABEL = 'IdenGraph';
const PACKAGE_NAME = 'idengraph';
const STATUS_COMMAND = 'idengraph.showStatus';
const RELOAD_COMMAND = 'workbench.action.reloadWindow';

/**
 * O servidor MCP é um pacote Python executado via `uvx`. A extensão não o
 * substitui: ela apenas o registra no VS Code e cuida da experiência de
 * pré-requisitos, para que uma máquina sem `uv` ou sem sessão do Azure CLI
 * receba uma orientação clara em vez de uma falha de processo.
 */
export function activate(context: vscode.ExtensionContext): void {
	const didChangeEmitter = new vscode.EventEmitter<void>();
	const output = vscode.window.createOutputChannel(SERVER_LABEL);
	const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
	statusBar.command = STATUS_COMMAND;
	statusBar.tooltip = 'Show IdenGraph readiness status';
	statusBar.text = '$(shield) IdenGraph';
	statusBar.show();

	context.subscriptions.push(
		output,
		statusBar,
		vscode.workspace.onDidChangeConfiguration(event => {
			if (event.affectsConfiguration('idengraph')) {
				didChangeEmitter.fire();
			}
		}),
		vscode.commands.registerCommand(STATUS_COMMAND, async () => {
			const readiness = await getReadiness();
			writeStatus(output, readiness);
			output.show(true);
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

	void showFirstRunGuidance(context);
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

interface Readiness {
	readonly uvAvailable: boolean;
	readonly azureSignedIn: boolean;
	readonly usingMock: boolean;
}

async function getReadiness(): Promise<Readiness> {
	const usingMock = vscode.workspace.getConfiguration('idengraph').get<boolean>('useMockData', false);
	const uvAvailable = await isCommandAvailable('uvx', ['--version']);
	const azureSignedIn = usingMock ? false : await isAzureSignedIn();

	return { uvAvailable, azureSignedIn, usingMock };
}

function writeStatus(output: vscode.OutputChannel, readiness: Readiness): void {
	const azureStatus = readiness.usingMock
		? 'Not required (mock data is enabled)'
		: readiness.azureSignedIn
			? 'Authenticated'
			: 'Not authenticated - run "az login" in a terminal';

	output.clear();
	output.appendLine('IdenGraph readiness status');
	output.appendLine('=========================');
	output.appendLine('Extension: Active');
	output.appendLine('MCP definition: Registered with VS Code');
	output.appendLine(`uvx: ${readiness.uvAvailable ? 'Found' : 'Not found - install uv'}`);
	output.appendLine(`Azure CLI: ${azureStatus}`);
	output.appendLine('');
	output.appendLine('Connection check: Open a new GitHub Copilot Chat in Agent mode,');
	output.appendLine('then run /mcp. "IdenGraph" must appear in the server list.');
	output.appendLine('VS Code starts the MCP process only when Copilot needs one of its tools.');
}

async function showFirstRunGuidance(context: vscode.ExtensionContext): Promise<void> {
	const seenVersion = context.globalState.get<string>('onboardingVersion');
	const version = context.extension.packageJSON.version as string;
	if (seenVersion === version) {
		return;
	}

	await context.globalState.update('onboardingVersion', version);
	const choice = await vscode.window.showInformationMessage(
		'IdenGraph is registered with VS Code. Open a new GitHub Copilot Chat in Agent mode, then run /mcp to confirm it is connected.',
		'Show status',
		'Reload window'
	);
	if (choice === 'Show status') {
		await vscode.commands.executeCommand(STATUS_COMMAND);
	} else if (choice === 'Reload window') {
		await vscode.commands.executeCommand(RELOAD_COMMAND);
	}
}
