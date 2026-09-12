# Arquitetura

O SentinelCMD 0.1 mantém um núcleo Python pequeno e substituível:

```text
CLI/menu
   │
   ├── Monitor (worker cooperativo, lock de instância, saúde)
   │      ├── ProcessCollector ─┐
   │      ├── NetworkCollector  ├─> RuleEngine ─> resposta opt-in
   │      └── FileCollector ────┘        │              ├─ FirewallManager
   │                                     │              └─ (quarentena/manual process)
   ├── SystemInspector (PowerShell fixo, somente leitura)
   └── EventStore (SQLite WAL, retenção, exportação, investigação)
```

`collectors` não persistem e não executam ações. `detection` recebe dicionários de eventos e retorna pontuação, risco, motivos e IDs de regra. `storage` é o único componente que grava o journal; a política de privacidade remove linha de comando por padrão. `response` não é chamado pelo motor diretamente: o monitor aplica a política de opt-in e só considera um bloqueio confirmado quando o gerenciador devolve uma regra própria criada ou já verificada.

Processos e conexões usam identidade `(pid, process_created_at)`. A correlação de rajadas exige o horário do pai e expira. Eventos de arquivo não recebem PID. O hash é lazy, com tamanho, tempo, quantidade por lote e cache limitados.

O limite entre observação e enforcement é intencional: `scan` nunca responde; `run` pode bloquear somente IP público explicitamente listado em `blocked_ips` com `auto_block_ips=true` e IOC crítico. Quarentena e término de processo são comandos manuais que exigem confirmação.

Cada camada tem uma superfície de migração clara. Um coletor futuro pode produzir o mesmo contrato de evento; o motor e o journal não precisam conhecer a implementação nativa. Um componente nativo deve manter os mesmos limites, identidade, ausência de rede externa e falhas explícitas.
