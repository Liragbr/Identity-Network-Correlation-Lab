# Relatório de investigação | Identity & Network Correlation Lab

> Execução própria em loopback. Serviços e contas fictícios. Não é incidente corporativo.

## Escopo e cadeia de evidências

- Eventos observados por serviços locais: **31**
- Origens de teste distintas: **3**
- Fonte primária: `events.jsonl` (auditoria emitida pelos listeners)
- Extração e ordenação: `timeline.csv`
- Resultado determinístico sobre a mesma telemetria: `findings.json`

## Resultado das detecções

| Regra | Ocorrências |
| --- | ---: |
| password_spray_pattern | 1 |
| reverse_dns_discovery | 1 |
| service_connectivity_sweep | 1 |

## Correlação multissinal

- Origem: `127.0.0.2`
- Sinais: `password_spray_pattern, reverse_dns_discovery, service_connectivity_sweep`
- Evidências associadas: **19** registros
- Interpretação: Correlated suspicious activity; identity compromise and lateral movement remain unproven.


## Achados por origem

### password_spray_pattern | 127.0.0.2

- Técnica MITRE hipotética: `T1110.003`
- Janela: `2026-11-20T14:02:42.602Z` a `2026-11-20T14:02:42.606Z`
- Eventos: **8**; valores distintos: **8**
- Autenticações bem-sucedidas da mesma origem na janela: **0**
- Evidência rastreável: `evt-00012, evt-00013, evt-00014, evt-00015, evt-00016, evt-00017, evt-00018, evt-00019`

**Interpretação:** Suspicious behavior observed; successful unauthorized access is NOT established.

### reverse_dns_discovery | 127.0.0.2

- Técnica MITRE hipotética: `T1018`
- Janela: `2026-11-20T14:02:42.606Z` a `2026-11-20T14:02:42.607Z`
- Eventos: **7**; valores distintos: **7**
- Autenticações bem-sucedidas da mesma origem na janela: **0**
- Evidência rastreável: `evt-00020, evt-00021, evt-00022, evt-00023, evt-00024, evt-00025, evt-00026`

**Interpretação:** Suspicious behavior observed; successful unauthorized access is NOT established.

### service_connectivity_sweep | 127.0.0.2

- Técnica MITRE hipotética: `T1046`
- Janela: `2026-11-20T14:02:42.607Z` a `2026-11-20T14:02:42.607Z`
- Eventos: **4**; valores distintos: **4**
- Autenticações bem-sucedidas da mesma origem na janela: **0**
- Evidência rastreável: `evt-00027, evt-00028, evt-00029, evt-00030`

**Interpretação:** Suspicious behavior observed; successful unauthorized access is NOT established.

## Avaliação

A autenticação falha distribuída entre várias identidades e a atividade de descoberta
exigem investigação. Nenhuma dessas evidências comprova uso de credenciais válidas
por agente não autorizado, execução remota ou movimento lateral.

A autenticação bem-sucedida de uma **outra origem** não pode ser vinculada ao host
investigado apenas pela proximidade temporal.

## Ações recomendadas no cenário

1. Revisar histórico de autenticações por origem e principal; validar origem real e NAT.
2. Correlacionar identidade/EDR com atividades de rede antes de inferir comprometimento.
3. Verificar autorização de ferramentas de inventário e rotinas de autenticação.
4. Confirmar com o responsável e seguir o fluxo de contenção baseado em criticidade.

## Limitações

- O serviço de identidade é **HTTP local**, não Active Directory/LDAP/NTLM/Kerberos.
- O DNS PTR utiliza datagramas DNS reais, mas um responder mínimo restrito ao loopback.
- TCP mostra conexões aceitas por serviços locais, não enumeração completa de portas fechadas.
- Resultados não são métricas de precisão/recall em ambiente de produção.
- Ausência de senha nos logs impede comprovar reutilização de uma mesma senha.
- Sem contexto EDR/host, não é possível inferir execução remota.
