# SentinelCMD

SentinelCMD é uma camada adicional, leve e local de observação e resposta defensiva para Windows 10 e Windows 11. Ele roda no CMD ou no PowerShell, registra eventos em SQLite e ajuda a investigar processos, conexões, arquivos e indicadores fornecidos pelo usuário. Um alerta heurístico é um pedido de investigação; não é um diagnóstico de malware e não promete proteção contra todos os ataques.

O projeto não explora vulnerabilidades, cria payloads, captura teclas, coleta credenciais, faz força bruta, testa máquinas externas ou tenta contornar antivírus/EDR. A coleta é local e passiva. O firewall auxiliar só administra regras de saída que pertencem ao grupo `SentinelCMD`; o bloqueio automático vem desligado.

## Início rápido

Requisitos: Windows 10/11, Python 3.12 ou superior e uma conta com permissão para ler os dados que você quer observar.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe sentinel.py
```

Depois da instalação, o executável `sentinel` fica disponível no ambiente virtual:

```powershell
.\.venv\Scripts\sentinel.exe status
.\.venv\Scripts\sentinel.exe run
```

`python sentinel.py` abre o menu interativo. `Ctrl+C` encerra o monitor. O processo roda em primeiro plano; a versão 0.1 não instala serviço, driver, tarefa agendada ou inicialização automática.

Para manter o estado em um diretório de laboratório:

```powershell
python sentinel.py --data-dir C:\SentinelLab\state scan
python sentinel.py --data-dir C:\SentinelLab\state processes --tree
python sentinel.py --data-dir C:\SentinelLab\state logs --limit 50
```

O diretório padrão é `%LOCALAPPDATA%\SentinelCMD`. O banco, o log rotativo, a configuração e a quarentena ficam ali. Não coloque esse diretório em uma unidade de rede ou em uma pasta que outro usuário possa alterar.

O status `STARTING` aparece durante o inventário inicial; `MONITORING` indica coleta ativa sem erro conhecido; `DEGRADED` indica cobertura reduzida; `STOPPED` indica que a proteção está parada.

## Comandos

| Comando | Uso |
| --- | --- |
| `run [--duration SEGUNDOS]` | inicia a proteção em primeiro plano |
| `status` | mostra estado, cobertura e contadores UTC |
| `scan` | analisa processos e sockets acessíveis sem resposta automática |
| `processes [--tree] [--watch SEGUNDOS]` | lista processos ou a árvore observada |
| `network [--watch SEGUNDOS]` | lista sockets TCP/UDP locais |
| `files status\|add\|remove` | consulta ou altera o escopo explícito de arquivos |
| `threats` / `logs` | lista alertas ou todos os eventos |
| `investigate EVENT_ID` | mostra cadeia de processo e linha do tempo limitada ao journal |
| `quarantine list\|add\|restore\|delete` | ações manuais, com confirmação |
| `firewall list\|block\|remove` | regras próprias do SentinelCMD; requer elevação para alterar |
| `rules list\|enable\|disable` | consulta e desabilita regras heurísticas conhecidas |
| `system` | consulta Defender, perfis do firewall e histórico de hotfix |
| `export ARQUIVO` | exporta JSON ou CSV sem sobrescrever arquivo existente |
| `config show\|set` | exibe ou altera a configuração validada |
| `terminate PID --created-at EPOCH` | encerramento manual, com identidade e confirmação |

Exemplos:

```powershell
python sentinel.py scan
python sentinel.py threats --limit 20 --json
python sentinel.py investigate 0123456789abcdef0123456789abcdef
python sentinel.py files add C:\Users\Alice\Downloads
python sentinel.py config set auto_block_ips true
python sentinel.py export C:\SentinelLab\report.json --format json --alerts-only
```

Comandos que modificam arquivos, processos ou firewall exigem `--yes` somente quando executados sem terminal interativo. A quarentena nunca é automática. O encerramento de processo é sempre manual e não usa `kill` forçado.

## Como a proteção funciona

O worker faz polling cooperativo com intervalos configuráveis. A primeira amostra cria uma linha de base; ela é investigada como observação do estado atual, sem inventar eventos de início. Amostras posteriores produzem deltas. Cada processo é identificado por PID e horário de criação para reduzir erros quando o Windows reutiliza um PID. O timestamp do evento é o momento da observação, não o instante exato em que a ação ocorreu.

O motor de risco usa regras declarativas em [`sentinelcmd/detection/rules.json`](sentinelcmd/detection/rules.json). Sinais que pertencem ao mesmo grupo contam uma vez. Evidências independentes podem se acumular durante cinco minutos, com memória limitada. Um hash ou IP exato que o usuário colocou em uma lista de bloqueio é um IOC configurado e pode ser crítico sozinho. A ferramenta não chama um processo de malware apenas por uma heurística.

Os sinais incluídos são:

- executável em `Temp` ou `AppData`;
- nome que imita componentes do Windows fora dos diretórios esperados;
- combinações incomuns de argumentos do PowerShell, `mshta` e `rundll32`;
- execução recente de arquivo com `Zone.Identifier` (quando o ADS está acessível);
- rajada de processos filhos com pai e horário de criação conhecidos;
- nome de arquivo com dupla extensão executável;
- SHA-256 ou IP nas listas locais configuradas.

SHA-256 é calculado sob demanda, com limite de tamanho, orçamento por ciclo e cache limitado. A ausência de hash é explicitamente registrada e não significa aprovação.

## Escopo e limitações

Processos e sockets são coletados com `psutil`. Permissões podem ocultar linhas de comando, usuários, proprietários de sockets ou processos protegidos. Sockets UDP sem peer não têm destino remoto. Polling não vê um processo ou conexão que nasce e termina entre duas amostras.

O monitor de arquivos não tem escopo implícito: só percorre diretórios locais colocados em `monitor_paths`. Ele compara metadados, ignora links, junctions, pontos reparse, UNC e unidades mapeadas, e não atribui PID a uma alteração. Orçamento de tempo, `max_files`, `max_entries` e `max_depth` limitam o impacto, mas uma única chamada do sistema pode ultrapassar o orçamento. Um ciclo incompleto sinaliza cobertura parcial e suprime deleções para evitar falsos eventos.

As consultas de segurança são somente leitura. `system` não altera Defender, firewall ou atualizações; histórico de hotfix não prova que há conformidade de patches. Regras locais do firewall podem ser alteradas por política de domínio ou por um firewall desabilitado.

Veja a operação detalhada, o modelo de cobertura e o benchmark reprodutível em [`docs/WINDOWS.md`](docs/WINDOWS.md).

Os campos, ações, níveis de risco e um evento sintético estão especificados em [`docs/SCHEMA.md`](docs/SCHEMA.md).

## Dados, privacidade e recuperação

O journal usa SQLite com WAL, índices por tempo/PID/risco, retenção e limite de eventos. Por padrão, linhas de comando completas não são persistidas. Ao habilitar `store_command_lines`, flags comuns de segredo são substituídas por `[REDACTED]`, mas nenhuma técnica identifica todos os segredos posicionais; use essa opção somente em laboratório. Exportações CSV protegem células que poderiam ser interpretadas como fórmulas.

A quarentena copia bytes para um diretório privado, verifica SHA-256 e só remove o original depois da verificação. Restauração usa criação exclusiva e nunca sobrescreve um arquivo existente. Blobs não são criptografados e não preservam ADS, ACLs, timestamps ou permissões de execução; um administrador ou o mesmo usuário com acesso ao diretório está fora da fronteira de isolamento. Estados `prepared`, `copy_only` e `recovery_required` ficam no manifest para recuperação manual.

## Configuração

O primeiro uso cria `config.json` validado. Todas as opções são limitadas; regras não executam código da configuração.

```json
{
  "process_interval": 3.0,
  "network_interval": 5.0,
  "file_interval": 10.0,
  "monitor_paths": ["C:\\Users\\Alice\\Downloads"],
  "max_files": 10000,
  "max_entries": 10000,
  "max_depth": 8,
  "file_scan_budget_ms": 100,
  "max_hash_mb": 64,
  "hashes_per_cycle": 4,
  "max_events": 50000,
  "retention_days": 30,
  "store_command_lines": false,
  "rules_enabled": true,
  "disabled_rules": [],
  "allowed_paths": [],
  "allowed_hashes": [],
  "blocked_hashes": [],
  "blocked_ips": [],
  "child_threshold": 12,
  "child_window_seconds": 60,
  "auto_block_ips": false,
  "log_connections": true
}
```

`allowed_paths` exige caminho absoluto e respeita a fronteira do diretório. `blocked_hashes` exige SHA-256 completo. `blocked_ips` aceita IP literal, sem DNS ou CIDR; o bloqueio automático ainda recusa loopback, privado, link-local, multicast, reservado e indefinido. Consulte [`docs/WINDOWS.md`](docs/WINDOWS.md) para limites de cada coletor.

## Desenvolvimento

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m build
```

Os testes usam dados sintéticos, diretórios temporários e mocks para firewall, processos e PowerShell. Nenhum teste cria uma regra real, encerra processo real ou acessa um destino externo. A matriz manual de VM Windows 10/11 e o benchmark estão em [`docs/WINDOWS.md`](docs/WINDOWS.md). Contribuições devem manter a coleta local, a ausência de comandos shell interpolados e os limites de consumo descritos em [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licença e segurança

O código é distribuído sob MIT. Consulte [`SECURITY.md`](SECURITY.md) para reportar vulnerabilidades do projeto sem publicar detalhes exploráveis em uma issue.
