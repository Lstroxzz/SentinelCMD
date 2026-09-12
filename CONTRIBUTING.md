# Contribuindo

SentinelCMD aceita melhorias de observação local, testes, documentação, acessibilidade do terminal e redução de custo. Antes de implementar, leia o README e [`docs/WINDOWS.md`](docs/WINDOWS.md). Mudanças que expandam o escopo para rede externa, exploração, evasão, roubo de credenciais ou persistência maliciosa não fazem parte do projeto.

## Ambiente

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m build
```

Os testes devem ser determinísticos e locais. Use `tmp_path`, dados sintéticos e mocks para PowerShell, firewall e processos. Não crie regras reais, não termine processos reais, não abra conexões externas e não leia o inventário da máquina do desenvolvedor em testes unitários. Casos manuais de Windows devem usar uma VM descartável e arquivos benignos.

## Diretrizes de implementação

- Preserve a separação entre coletores, detecção, armazenamento e resposta para permitir uma futura migração de componentes críticos para Rust, Go ou C++.
- Mantenha polling, filas, caches, hashes, retenção e saídas com limites explícitos.
- Use PID junto com `process_created_at`; nunca atribua alteração de arquivo a um PID sem evidência.
- Não interpolar entrada do usuário em comandos PowerShell. Valide IPs, hashes, IDs e caminhos antes de qualquer resposta.
- Respostas automáticas devem ser opt-in, idempotentes, auditáveis e reversíveis quando possível. Não adicione encerramento automático de processos.
- Não registre linha de comando completa por padrão. Se um teste precisar de armazenamento opt-in, use segredos fictícios e verifique a redação.
- Mensagens exibidas no terminal devem neutralizar caracteres de controle; dados CSV precisam de proteção contra injeção de fórmula.
- Atualize a documentação de limitações quando mudar cobertura, privilégio, retenção ou consumo.

Commits pequenos e uma descrição objetiva ajudam na revisão. Um pull request deve explicar comportamento antes/depois, riscos, testes executados e qualquer dependência nova. Mudanças de regra devem incluir casos benignos e justificar como sinais independentes são combinados; uma heurística isolada não deve afirmar malware.
