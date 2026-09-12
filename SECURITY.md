# Política de segurança

SentinelCMD é software defensivo de monitoramento local. Não envie amostras de credenciais, dados pessoais ou arquivos de usuários em um relatório público. O projeto não aceita contribuições de exploração, payloads, evasão, captura de credenciais, persistência maliciosa, força bruta, DDoS ou interação ofensiva com máquinas de terceiros.

Para relatar uma vulnerabilidade no SentinelCMD, abra um contato privado com os mantenedores do repositório GitHub antes de criar uma issue pública. Se o repositório ainda não tiver um canal privado configurado, abra uma issue sem reproduzir o segredo e escreva apenas “solicito canal privado de segurança”. Inclua:

- versão, sistema operacional e forma de instalação;
- componente e impacto observado;
- passos mínimos reproduzíveis usando arquivos/hosts locais e benignos;
- logs sanitizados, sem comandos completos, tokens, nomes de usuário ou caminhos pessoais;
- uma sugestão de correção, se já houver.

Não execute demonstrações contra computadores externos. Os mantenedores confirmarão o recebimento, avaliarão o impacto e publicarão uma correção ou orientação de mitigação quando apropriado. As respostas de firewall e quarentena são deliberadas e limitadas ao escopo documentado; uma regra heurística não deve ser usada como prova de comprometimento.

O banco SQLite, o log e os blobs de quarentena podem conter caminhos, PID, horários, hashes e endereços observados. Proteja o diretório de dados com ACLs apropriadas e remova dados de laboratório conforme a política da sua organização.
