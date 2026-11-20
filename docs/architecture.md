# Arquitetura e proveniência das evidências

## Componentes

| Componente | Implementação | Dados que produz | Evidência independente? |
| --- | --- | --- | --- |
| Identity gateway | `ThreadingHTTPServer`, HTTP POST `/auth` | origem TCP vista pelo servidor, principal, resposta 200/401, UTC | Sim: resposta efetiva do serviço local |
| DNS PTR | servidor UDP com wire format DNS PTR/IN | endereço IP de origem, nome reverso requisitado, resposta emitida | Sim: datagrama DNS local recebido |
| Serviços TCP | quatro listeners com portas efêmeras | endereço de origem e porta local que aceitou `connect()` | Sim: conexão aceita pelo serviço |
| Audit sink | JSON Lines + lock de threads | campos e ID únicos para cada evento | Agrega os registros dos serviços |
| Correlator | janela deslizante por `src_ip` | agrupamento e IDs dos eventos associados | Interpretação, não fonte independente |
| Reporter | Markdown, CSV, JSON | linha do tempo, hipóteses, ressalvas | Derivado dos eventos originais |

## Modelo de confiança

O endereço de origem vem da API de socket do servidor (`client_address` ou `recvfrom`), não de um header `X-Forwarded-For` controlável pelo cliente. O endereço IP continua sendo um identificador de rede, não uma prova de identidade humana: proxies, NAT e roteamentos podem tornar a atribuição ambígua fora do laboratório.

O gateway de identidade conhece contas **fictícias** incorporadas no código. Os segredos de demonstração são constantes no script de cenário porque o ambiente é exclusivamente local; **nenhum segredo é registrado nos eventos**. O gateway não implementa SSO, LDAP, autenticação de produção nem política de lockout.

## Schema dos eventos

```json
{
  "event_id": "evt-00012",
  "timestamp": "<ISO8601 UTC com Z>",
  "event_type": "auth",
  "src_ip": "127.0.0.2",
  "dst_ip": "127.0.0.1",
  "service": "identity-gateway",
  "result": "denied",
  "principal": "lab.user01",
  "http_status": 401
}
```

A camada de ingestão rejeita JSON inválido, timestamps sem timezone, eventos muito grandes, ausência de campos obrigatórios e tipos desconhecidos. A extração para CSV é uma visualização, não a fonte primária.

## Reprodutibilidade

- Portas são escolhidas pelo SO, evitando conflito e evitando configuração manual.
- `run` não recebe IPs de destino; todas as conexões ficam em `127/8`.
- `verify` recalcula achados usando o `events.jsonl` de uma execução anterior.
- A CI compara a igualdade lógica dos achados de `run` e `verify`.
- Timestamps UTC e portas efêmeras variam entre execuções. O **comportamento esperado**, contagens e hipóteses não variam.

## Captura de pacotes opcional

Um operador pode capturar a interface `lo` em outra sessão Linux com Wireshark/TShark/tcpdump, se possuir permissões, e visualizar HTTP, DNS e TCP. Essa captura é **opcional** e não faz parte dos artefatos versionados. A execução é rápida, portanto deve-se iniciar a captura antes de `run`. Capturas da interface inteira podem conter tráfego local de outros processos: revise antes de compartilhar. Não é necessário privilegio de root para executar o laboratório em si.

## Limites do modelo

Os listeners modelam observáveis de autenticação e descoberta, não protocolos corporativos complexos. O laboratório não possui dados de EDR, RPC Endpoint Mapper, SMB Session Setup, RootDSE ou eventos de Windows Security. Não atribuir essas fontes ao projeto. Não utilizar o ambiente como benchmark de produtos NDR ou EDR.
