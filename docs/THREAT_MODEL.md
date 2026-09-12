# Modelo de ameaças e limites

O ativo principal é a integridade e a explicabilidade do journal local. O SentinelCMD considera um usuário comum, um processo local não confiável e mudanças benignas de software. Ele tenta reduzir falsos positivos por identidade de processo, grupos de evidência, allowlists e estados de cobertura.

Ele não é uma barreira de segurança contra administrador, SYSTEM, outro processo com os mesmos direitos que substitua arquivos durante uma corrida, políticas de domínio que substituam firewall, rootkits, drivers, kernel comprometido ou um atacante que desligue o processo. Polling em espaço de usuário perde eventos muito curtos e não prova causalidade de arquivos. A quarentena protege contra execução acidental pelo fluxo normal do SentinelCMD, mas seus blobs não são criptografados e a ACL não é uma fronteira contra administradores.

O projeto não faz reputação online, DNS, captura de pacotes, exploração, varredura de terceiros, coleta de credenciais ou persistência. A ausência de alerta, hash, usuário, caminho, proprietário de socket ou estado do Defender é desconhecida; ela nunca é convertida em “seguro”.

Ao avaliar um incidente, preserve o `event_id`, timestamp UTC, identidade `(pid, process_created_at)`, hash quando disponível, caminho, IP/porta/protocolo, motivos, regras, cobertura e ação. Trate `coverage_reduced`, `hash_status` e `DEGRADED` como parte da evidência. Confirme manualmente contra o sistema operacional e outras ferramentas antes de remover arquivos ou bloquear tráfego.
