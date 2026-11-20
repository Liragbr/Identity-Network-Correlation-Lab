# Detection Engineering: critérios, tuning e limites

## 1. Hipótese de password spraying

**Critério:** uma origem que acumula pelo menos seis autenticações negadas associadas a seis principais distintos dentro de janela móvel de 120 s. É uma **heurística de distribuição de falhas**, não prova de que a mesma senha foi usada, pois o serviço não armazena senhas.

**Falsos positivos plausíveis:** testes homologados de autenticação, gateways corporativos que compartilham endereço de saída, robôs de inventário e concentrações de usuários por NAT/CGNAT.

**Tuning:** enriquecer por identidade do dispositivo, contexto de autenticação e padrão histórico; não basear allowlists permanentes somente em ASN/IP; comparar taxa de falha por principal, mudanças ao longo do tempo e sinais EDR.

**Controle negativo implementado:** oito tentativas negadas contra **uma** conta de serviço não geram `password_spray_pattern`.

## 2. Descoberta de sistemas por DNS PTR

**Critério:** pelo menos cinco nomes de consulta PTR distintos vindos da mesma origem em 120 s.

**Limite:** resoluções reversas podem ser realizadas por serviços legítimos de gestão, auditoria, inventário ou diagnóstico. O critério é um **sinal de descoberta**, não indicação suficiente de atividade hostil.

## 3. Descoberta de serviços por conexão TCP

**Critério:** ao menos três portas de destino distintas com conexão TCP aceita por listeners locais em 120 s. Não captura portas fechadas nem SYNs incompletos. Portas são efêmeras, de forma que o detector mede diversidade de serviços, não portas 135/389/445 de protocolos específicos.

## 4. Correlação e qualificação do incidente

Uma segunda etapa exige os três sinais, **mesma origem** e amplitude temporal total de até 120 s. Ela gera um objeto `correlations` rastreável pelos `evidence_ids`. Os três sinais em uma mesma origem e janela temporal elevam a prioridade investigativa, mas **não demonstram acesso não autorizado ou movimento lateral consumado**. Um login `success` observado em outra origem não eleva o status da origem investigada. Um login `success` na mesma origem exige verificação de contexto, autorização e se houve ação pós-autenticação.

A saída de cada achado contém `evidence_ids` que podem ser relacionados com o JSONL original. Isso reduz decisões feitas somente com base em sumários.

## 5. MITRE ATT&CK

| Técnica | Correlação | Ressalva |
| --- | --- | --- |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | falhas em múltiplas identidades | compatível com spray; senha comum não observável |
| [T1018](https://attack.mitre.org/techniques/T1018/) | variação de DNS PTR | inventário legítimo pode produzir o mesmo comportamento |
| [T1046](https://attack.mitre.org/techniques/T1046/) | conexões a serviços distintos | conexões completadas não provam execução adversária |

## 6. Sigma

`sigma/lab_auth_denied.yml` seleciona eventos de um schema **do laboratório**. `sigma/lab_password_spray_correlation.yml` aplica `value_count` com `field: principal`, `group-by: src_ip` e `timespan: 2m`, de acordo com as construções de correlação SigmaHQ.

Isso é uma **regra candidata** para integração, não um alerta pronto para instalar em qualquer SIEM. Seria necessário testar compatibilidade de backend, pipeline de normalização e campos reais, além de tuning de ambiente antes de habilitar resposta automática.

## 7. Qualidade de validação

Os testes automatizados cobrem threshold, limite exato de janela, eventos fora da janela, exclusão de origens distintas, repetição em uma só conta, DNS PTR repetido e porta repetida. O conjunto deliberadamente **não calcula** precisão, recall, FPR, MTTD ou MTTR de produção: seriam métricas inválidas sobre um cenário de controle pequeno.
