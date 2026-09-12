# Windows: operação, cobertura e validação

O SentinelCMD 0.1 é uma camada adicional de observação e resposta local para
Windows 10 e Windows 11, com Python 3.12 ou superior. Não substitui o Microsoft
Defender, outro antivírus, o Windows Firewall, atualizações ou backups. Um
indicador heurístico indica necessidade de investigação; não prova malware.

## Execução e privilégios

No diretório do projeto, crie um ambiente isolado e instale o pacote:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe sentinel.py
```

O comando instalado também funciona sem ativar o ambiente:

```powershell
.\.venv\Scripts\sentinel.exe
```

O monitor roda no processo do terminal. Iniciar a proteção inicia uma thread de
coleta; fechar o programa encerra essa proteção. Esta versão não instala driver,
serviço do Windows, tarefa agendada ou mecanismo de inicialização automática.
O estado `MONITORING` significa que o laço está ativo, sem erro conhecido de
cobertura; não é uma certificação de segurança. `DEGRADED` indica cobertura
reduzida; examine os motivos. `STOPPED` significa monitoramento interrompido.
Durante o inventário inicial o estado pode ser `STARTING`; isso não representa
uma conclusão de cobertura até que os coletores publiquem seu primeiro estado.

Comece com uma conta comum. Caminhos de executáveis, argumentos, usuários e
proprietários de sockets podem ficar indisponíveis por permissões. Processos
protegidos podem continuar inacessíveis mesmo com elevação. O programa não
solicita credenciais nem tenta contornar essas restrições.

| Operação | Privilégio e efeito |
| --- | --- |
| Processos e sockets locais | Leitura; permissões determinam a cobertura. |
| Arquivos configurados | Requer leitura de metadados no caminho; não concede acesso adicional. |
| Verificações de segurança | Consultas de leitura; módulos ou permissões ausentes ficam indisponíveis. |
| Quarentena/restauração | Requer acesso aos arquivos e diretórios envolvidos; altera arquivos somente pela ação solicitada. |
| Encerramento de processo | Requer permissão sobre o processo e passa pelas restrições de identidade e processos críticos. |
| Adicionar/remover regra de firewall | Requer terminal elevado; modifica somente regras reconhecidas do grupo SentinelCMD. |

O bloqueio automático de IPs vem desativado. Quando habilitado explicitamente,
depende dos indicadores locais configurados e dos limites do mecanismo de
resposta. Uma regra criada não demonstra que um pacote foi efetivamente
bloqueado: o Windows Firewall precisa estar habilitado e políticas de domínio
podem alterar o efeito das regras locais.

## O que cada coletor observa

### Processos

O coletor enumera PID, PID pai, nome, caminho e início do processo por `psutil`.
Argumentos e usuário são consultados quando uma identidade é vista pela
primeira vez. A identidade usa PID e horário de criação para reduzir a
atribuição de eventos a um PID reutilizado. O início do pai é incluído quando o
pai está no inventário e foi criado antes do filho.

A primeira amostra estabelece a linha de base sem inventar eventos de início.
O monitor analisa o inventário inicial como observação de processos já
existentes. As amostras seguintes indicam inícios e encerramentos observados.
A árvore mostra somente os processos acessíveis naquele inventário; pais já
encerrados e processos não observados podem resultar em cadeias incompletas.

`timestamp` é o momento UTC em que o SentinelCMD observou o fato, não o instante
exato de uma ação. `process_created_at` é o horário de criação fornecido pelo
sistema operacional, em segundos Unix. Um encerramento é inferido pelo
desaparecimento entre inventários; não há telemetria do instante de término.

O marcador de download exige `Zone.Identifier` com `ZoneId` 3 ou 4 e modificação
do arquivo nas últimas 24 horas. A consulta lê no máximo 4 KiB desse fluxo.
Essa data é uma aproximação, não um registro confiável do download. A marca
pode não existir, ter sido removida ou ter seu horário alterado. Ausência de
marca não significa arquivo seguro. Apenas caminhos locais sem componentes
reparse conhecidos são elegíveis para essa leitura.

### Rede

O coletor observa a tabela local de sockets IPv4/IPv6 TCP e UDP: endereços,
portas, estado e proprietário quando acessível. Não captura pacotes, faz
resolução DNS, consulta reputação online, envia probes ou conecta a destinos
para investigação. O proprietário é correlacionado por PID e início do
processo, quando ambos estão disponíveis.

Sockets UDP não conectados e sockets de escuta podem ter IP e porta remotos
ausentes. Isso é esperado e não indica ocultação. `NONE` em UDP não corresponde
a uma sessão TCP estabelecida. Estados mudando na mesma combinação de
endpoints não geram artificialmente uma nova conexão. Uma reconexão com a mesma
identidade e endpoints entre duas amostras pode não ser distinguível.

### Arquivos

Nenhum diretório é monitorado por padrão. `monitor_paths` aceita diretórios
locais absolutos escolhidos pelo usuário. A coleta compara tamanho e horário de
modificação; não lê o conteúdo de cada arquivo. Criações, alterações e deleções
não incluem PID presumido: somente metadados não demonstram qual processo fez
a alteração.

O percurso ignora links simbólicos, junctions, pontos reparse e caminhos de rede,
inclusive unidades mapeadas. Um caminho reparse trocado durante a observação é
uma limitação de uma coleta em espaço de usuário, sem um driver de auditoria.

| Configuração | Efeito |
| --- | --- |
| `monitor_paths` | Escopo explícito. Prefira diretórios pequenos e relevantes. |
| `max_files` | Máximo de metadados de arquivos mantidos por ciclo. |
| `max_depth` | Profundidade de subdiretórios; zero examina somente arquivos da raiz. |
| `max_entries` | Limita também diretórios vazios, entradas ignoradas e raízes. |
| `file_scan_budget_ms` | Orçamento cooperativo de tempo por chamada; o percurso continua depois. |
| `file_interval` | Espera entre chamadas do coletor, inclusive etapas de um ciclo incompleto. |

Um ciclo pode precisar de diversas chamadas. Eventos são apresentados ao
concluir o ciclo, portanto a latência pode exceder `file_interval`. Uma única
chamada ao sistema de arquivos pode ultrapassar o orçamento de tempo; este não
é um limite de tempo real imposto pelo kernel.

Se o limite de arquivos/entradas for atingido ou uma enumeração falhar, a
cobertura é parcial. O coletor suprime deleções nesse ciclo para não confundir
falta de acesso com exclusão. Após um ciclo incompleto, arquivos até então
desconhecidos são incorporados sem afirmar que acabaram de ser criados. Veja
`scanning`, `complete`, `truncated`, `inaccessible_entries`, `tracked_files` e
`last_scan_at` no estado do monitor de arquivos. Um diretório muito grande pode
ficar permanentemente fora da cobertura completa; reduza o escopo antes de
aumentar os limites.

Renomeações aparecem como exclusão/criação. Alterações que preservem tamanho e
mtime, assim como arquivos criados e apagados entre amostras, podem ser perdidas.

### Hashes e custo de disco

SHA-256 é calculado sob demanda pelo monitor, quando há indícios pertinentes ou
uma lista local de hashes bloqueados. `max_hash_mb` limita o tamanho elegível e
`hashes_per_cycle` limita tentativas por lote de análise. Há um orçamento
cooperativo de aproximadamente 250 ms por hash e cache limitado de resultados;
mudanças de tamanho ou mtime invalidam o cache. Operações de leitura bloqueadas pelo
sistema podem ultrapassar esse orçamento.

Um hash ausente não significa que um arquivo passou na análise. O evento
informa `hash_status`; arquivos grandes, sem acesso, modificados durante a
leitura ou que excedam o orçamento podem ficar sem hash. Listas de hashes não
são uma varredura completa de todos os executáveis do computador.

### Defender, firewall e atualizações

`System Security` executa um script PowerShell fixo, não interativo, sem
interpolar comandos recebidos do usuário e com timeout de 15 segundos. As
consultas são:

- `Get-MpComputerStatus`: disponibilidade do Defender, antivírus, proteção em
  tempo real e informação de assinatura.
- `Get-NetFirewallProfile`: configuração dos perfis de firewall.
- `Get-HotFix`: item mais recente do histórico acessível de hotfixes.

As consultas não alteram preferências, instalam atualizações ou iniciam scans do
Defender. Um antivírus de terceiros pode afetar o estado do Defender. Histórico
de hotfixes não identifica todas as atualizações pendentes e não comprova que o
sistema está atualizado; a resposta mantém `pending_updates_checked: false`.
Erros, timeout e módulos indisponíveis permanecem explícitos. Outros sistemas
operacionais recebem uma indicação de plataforma não suportada para essas
verificações.

## Validação em máquinas virtuais

Execute a matriz abaixo em uma VM Windows 10 e outra Windows 11. Registre a
edição, build, versão do Python/psutil, vCPUs, RAM, tipo de disco, nível de
privilégio e configuração do SentinelCMD. Use snapshot da VM para os testes
manuais de resposta e arquivos inofensivos criados para o laboratório. A suíte
automatizada substitui respostas ao sistema por mocks; não requer malware.

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m build
```

1. **Conta comum e elevada:** abra o menu, inicie e pare o monitor e consulte
   processos, árvore e sockets. Registre campos indisponíveis e erros de
   cobertura. Não interprete uma tela sem alertas como teste de proteção total.
2. **Processo benigno:** mantenha uma segunda instância Python ativa por mais de
   dois intervalos de coleta e verifique o início, PID, pai e encerramento:

   ```powershell
   .\.venv\Scripts\python.exe -c "import time; time.sleep(20)"
   ```

3. **Rede inteiramente local:** mantenha uma conexão TCP de loopback e confira
   seus endpoints. A porta é escolhida pelo sistema; nenhuma máquina externa é
   contatada:

   ```powershell
   .\.venv\Scripts\python.exe -c "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); c=socket.create_connection(s.getsockname()); p,_=s.accept(); print(s.getsockname()); time.sleep(20)"
   ```

   Verifique também UDP sem peer, sem enviar datagramas:

   ```powershell
   .\.venv\Scripts\python.exe -c "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print(s.getsockname()); time.sleep(20)"
   ```

4. **Arquivos:** crie `lab-watch` no diretório do projeto e configure seu caminho
   absoluto em `monitor_paths`. Espere a linha de base concluir. Crie um `.txt`,
   espere outro ciclo completo, altere seu conteúdo, espere e exclua esse mesmo
   arquivo. Confira os três eventos e a ausência de PID atribuído. Repita com
   limites pequenos para confirmar a indicação de cobertura parcial.
5. **Erros e parada:** execute os testes de permissões e enumeração simulada da
   suíte. Interrompa o monitor durante um ciclo de arquivos e confirme liberação
   dos handles e encerramento. Tente uma segunda instância com o mesmo diretório
   de dados e confirme a recusa de um segundo monitor.
6. **Respostas manuais na VM:** use apenas arquivo inofensivo do laboratório em
   quarentena/restauração e um processo de teste conhecido. Para firewall, use
   apenas um IP público de laboratório sob seu controle; criar/listar/remover
   uma regra não requer estabelecer conexão com ele. Confira que as demais
   regras permanecem intactas. Loopback, redes privadas e endereços reservados
   são recusados pelo gerenciador. Não habilite bloqueio automático para medir
   o custo normal do monitor.
7. **Persistência e privacidade:** exporte eventos, feche e reabra o programa e
   confira timestamps, identificação do evento, motivo e ação registrada.
   Confirme que argumentos completos não são persistidos com
   `store_command_lines: false`, que é o padrão.

Se o teste de criação de links for ignorado por falta de privilégios, registre
o skip e repita esse caso em uma VM autorizada com suporte a symlinks; um skip
não valida aquela cobertura. Fixtures sintéticas validam critérios de regras,
não taxas de detecção contra ameaças reais.

## Benchmark reprodutível

Meça o processo real do SentinelCMD. Não derive uma promessa de CPU/RAM de uma
única máquina. Separe o custo inicial de inventário/hash do consumo sustentado.
Para comparar versões, mantenha a mesma VM, carga, número aproximado de
processos/sockets, arquivos, intervalos, listas de indicadores e retenção.

Inicie o monitor pelo menu. Em outro PowerShell, identifique o PID correspondente
ao `sentinel.py`; não escolha automaticamente outra instância Python:

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Select-Object ProcessId, CommandLine
```

Salve o código abaixo como `benchmark.py` em uma pasta de trabalho sua. Ele
anexa somente ao PID informado, aguarda 30 segundos de aquecimento e mede cinco
minutos. Não modifica o processo observado.

```python
import json
import platform
import statistics
import sys
import time

import psutil

target = psutil.Process(int(sys.argv[1]))
identity = target.create_time()
time.sleep(30)
before = target.io_counters()
target.cpu_percent(None)
started = time.monotonic()
cpu, rss, handles = [], [], []
for _ in range(300):
    if not target.is_running() or target.create_time() != identity:
        raise SystemExit("O processo encerrou ou o PID foi reutilizado.")
    cpu.append(target.cpu_percent(interval=1))
    rss.append(target.memory_info().rss)
    handles.append(target.num_handles())
after = target.io_counters()
elapsed = time.monotonic() - started
ordered_cpu = sorted(cpu)
print(json.dumps({
    "windows": platform.platform(),
    "python": sys.version,
    "psutil": psutil.__version__,
    "logical_cpus": psutil.cpu_count(),
    "pid": target.pid,
    "process_created_at": identity,
    "measurement_seconds": elapsed,
    "cpu_percent_mean": statistics.mean(cpu),
    "cpu_percent_p95": ordered_cpu[int(0.95 * (len(cpu) - 1))],
    "rss_mib_mean": statistics.mean(rss) / 1024**2,
    "rss_mib_peak": max(rss) / 1024**2,
    "read_bytes_delta": after.read_bytes - before.read_bytes,
    "write_bytes_delta": after.write_bytes - before.write_bytes,
    "handles_first": handles[0],
    "handles_last": handles[-1],
    "handles_peak": max(handles),
}, indent=2))
```

Execute com o PID verificado, substituindo `12345`:

```powershell
.\.venv\Scripts\python.exe .\benchmark.py 12345 |
    Set-Content -Encoding utf8 .\benchmark-result.json
```

`cpu_percent` segue a convenção do psutil: 100% equivale ao uso integral de um
processador lógico e pode ultrapassar 100% em um processo com trabalho paralelo.
Não equivale automaticamente ao percentual normalizado exibido pelo Gerenciador
de Tarefas. RSS inclui o interpretador Python. Contadores de I/O são os do
processo e podem incluir acesso em cache; não medem diretamente o desgaste ou
throughput físico do SSD. Filhos PowerShell de consultas manuais de sistema não
estão incluídos nas métricas do processo pai.

Faça três execuções por cenário: monitor parado, monitor ativo sem caminhos de
arquivos e monitor ativo com uma árvore de laboratório de tamanho conhecido.
Compare medianas entre execuções, registre dispersão e anexe a configuração
utilizada. Para investigar vazamentos, prolongue a medição e observe tendência
de RSS/handles e o crescimento do diretório de dados. Um aumento de RSS inicial
que estabiliza não demonstra, sozinho, vazamento.

CPU, RAM, disco e latência dependem do ambiente. Os limites configuráveis
controlam trabalho e retenção, mas não garantem um percentual fixo de recursos
nem detecção de todas as atividades.
