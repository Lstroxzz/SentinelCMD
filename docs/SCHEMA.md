# Esquema de eventos

O journal SQLite guarda uma linha JSON por evento. `schema_version` do arquivo exportado é `1`. Campos desconhecidos podem ser adicionados em versões futuras; consumidores devem ignorá-los. O exemplo abaixo usa dados sintéticos e não representa uma máquina real.

```json
{
  "id": "0123456789abcdef0123456789abcdef",
  "timestamp": "2026-01-15T12:34:56.789+00:00",
  "kind": "process_started",
  "pid": 4242,
  "ppid": 4000,
  "process_created_at": 1768480496.25,
  "parent_created_at": 1768480400.10,
  "process_name": "example.exe",
  "executable": "C:\\Users\\Alice\\Downloads\\example.exe",
  "file_path": null,
  "sha256": null,
  "hash_status": "not_computed",
  "command_line": null,
  "username": "EXAMPLE\\Alice",
  "local_ip": null,
  "local_port": null,
  "remote_ip": null,
  "remote_port": null,
  "protocol": null,
  "state": null,
  "score": 20,
  "risk": "low",
  "evidence_count": 1,
  "rule_ids": ["process_temp"],
  "reasons": ["Executável iniciado em pasta temporária; verificar origem."],
  "action": "alerted"
}
```

`timestamp` é UTC e representa a observação. `process_created_at` e `parent_created_at` são identidades em segundos Unix. Um PID sem horário de criação não é suficiente para correlação. `file_path` identifica uma alteração de arquivo, mas o evento não contém PID presumido. Em rede, `local_*`, `remote_*`, `protocol` (`TCP`/`UDP`) e `state` refletem a tabela local; um UDP não conectado pode ter destino nulo.

`score` fica entre 0 e 100. `risk` é `info`, `low`, `medium`, `high` ou `critical`. Regras do mesmo grupo contam uma vez. `critical` normalmente requer um IOC exato configurado ou três grupos independentes; uma heurística isolada permanece limitada. `rule_ids` e `reasons` explicam o que foi observado, não afirmam que o arquivo seja malware.

`action` pode ser `observed`, `alerted`, `coverage_reduced`, `firewall_blocked`, `firewall_already_blocked`, `auto_block_failed`, `auto_block_unconfirmed`, `quarantined`, `copy_only`, `restored`, `deleted`, `terminated`, `monitoring_started` ou `monitoring_stopped`. Uma ação `firewall_blocked` só é registrada quando o gerenciador confirma uma regra própria criada naquela operação. `firewall_already_blocked` é idempotência e não incrementa a contagem de novas regras.

O campo `command_line` é `null` por padrão. Quando `store_command_lines` está habilitado, o valor é truncado, caracteres de controle são neutralizados e flags comuns de segredo são substituídas por `[REDACTED]`; isso é uma proteção de melhor esforço, não uma garantia de que todos os segredos foram removidos. `hash_status` informa `computed`, `not_computed` ou `unavailable_or_budget_exceeded`; um valor ausente é desconhecido.

Eventos `collector_error` e o objeto `health` indicam cobertura reduzida. A ausência de um evento pode resultar de polling, permissões, processo protegido ou ciclo de arquivo incompleto. Use os campos de cobertura junto com o evento ao fazer uma investigação.
