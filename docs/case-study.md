# Case study: Authentication & Discovery Correlation

## Questão investigativa

Uma origem gera falhas de autenticação para várias identidades, consultas DNS reversas e conexões TCP a serviços distintos. A coincidência desses sinais demonstra um incidente de comprometimento?

**Não automaticamente.** O desafio é classificar o comportamento observado e indicar que evidências adicionais seriam necessárias antes de concluir uso indevido de credenciais ou execução remota.

## Condições de laboratório

- Todos os serviços são locais e controlados pelo próprio projeto.
- A origem `127.0.0.2` representa o fluxo investigado.
- `127.0.0.3` representa tráfego legítimo e uma autenticação bem-sucedida posterior.
- `127.0.0.4` representa uma configuração de serviço errada, com falhas repetidas na mesma conta.
- Nomes, contas e serviços são fictícios e não representam nenhuma organização.

## Hipóteses e interpretação

| Hipótese | Evidência a favor | Evidência insuficiente / controvérsia | Estado |
| --- | --- | --- | --- |
| Tentativa distribuída de acesso a várias identidades | 8 negações e 8 principais distintos na mesma origem | Não se registra a senha, nem se conhece contexto humano | Compatível, não confirmada |
| Descoberta de ativos | 7 requisições PTR distintas | Descoberta pode ser inventário legítimo | Observável, intenção desconhecida |
| Descoberta de serviços | 4 conexões TCP aceitas em portas distintas | Não há exploração nem execução remota | Observável, intenção desconhecida |
| Autenticação válida no host investigado | O laboratório contém sucesso de autenticação | Sucesso pertence a **outra origem** | Não demonstrada |
| Movimento lateral | Conexões a múltiplos serviços | Sem telemetria de execução, sessão remota ou mudança de estado | Não demonstrado |

## Cadeia de evidências

1. `events.jsonl`: evidência primária emitida pelos servidores ao receber requisições.
2. `timeline.csv`: ordenação temporal preservando identificadores de eventos.
3. `findings.json`: critérios de detecção e lista de `evidence_ids` por achado.
4. `case-report.md`: interpretação e limitações explícitas, geradas pelo correlator.

Uma revisão técnica deve **reproduzir** os resultados com `verify`, inspecionar os `evidence_ids` e contestar as inferências que extrapolem os eventos observados.

## Decisão analítica

**Classificação:** atividade suspeita de autenticação distribuída e descoberta em ambiente controlado. **Comprometimento de credenciais: não demonstrado. Movimento lateral: não demonstrado.**

**Próximos passos se esta telemetria fosse observada em produção:** validar NAT/atribuição de origem, correlacionar eventos dos controladores de domínio e EDR, verificar processos e tickets de mudança, avaliar acessos efetivamente autorizados e acionar o playbook de resposta segundo criticidade.

## Limitação de generalização

Os serviços simplificam autenticação e descoberta para permitir o teste de detecções sem um AD ou laboratório pesado. Não há dados corporativos, chamadas de API comercial, amostras de malware, tráfego de LDAP/SMB/RPC nem risco de atingir redes de terceiros. O case mostra **um procedimento reproduzível de investigação**, não a análise forense de um ambiente Windows real.
