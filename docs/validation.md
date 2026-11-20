# Validação do laboratório

## Comandos

```bash
export PYTHONPATH=src
python3 -m unittest discover -s tests -v
python3 -m soclab run --output artifacts
python3 -m soclab verify --events artifacts/events.jsonl --output artifacts/replay
```

## Critérios de aceitação

| ID | Teste | Resultado esperado |
| --- | --- | --- |
| V-01 | Execução dos serviços locais | 31 eventos em JSONL com origem TCP/UDP real |
| V-02 | Password spray pattern | 1 achado para `127.0.0.2` |
| V-03 | DNS PTR | 1 achado para `127.0.0.2` |
| V-04 | TCP service connectivity | 1 achado para `127.0.0.2` |
| V-05 | Falhas repetidas em uma única conta | Nenhum achado de spray para `127.0.0.4` |
| V-06 | Autenticação legítima | Sucesso de `127.0.0.3` não atribuído a `.2` |
| V-07 | Replay do arquivo primário | `findings.json` logicamente igual ao de execução direta |
| V-08 | Limites das janelas móveis | Inclusão/exclusão testadas em unittest |
| V-09 | Schema de ingestão | JSON inválido, timestamp sem timezone e eventos gigantes rejeitados |
| V-10 | Segredos em logs | Strings de senhas de teste ausentes do JSONL |
| V-11 | Correlação multissinal | 1 correlação na origem investigada e 0 em outras origens |

## Evidência de execução

Os arquivos de `examples/` são uma amostra do resultado efetivamente produzido durante o desenvolvimento. Eles podem ser reprocessados sem rede com `verify`. A validação **pessoal** do autor ao publicar exige executar o mesmo teste no próprio ambiente e conferir os resultados.

## Mudanças esperadas entre execuções

UTC absoluto e portas efêmeras mudam a cada execução. A comparação de replay usa o **mesmo arquivo JSONL** para garantir igualdade dos achados. Não compare timestamps ou portas entre execuções novas.

## Escopo de qualidade

A suíte mede comportamento funcional e regressões deste protótipo, não sensibilidade ou especificidade de regras para redes empresariais. Um ambiente corporativo exigiria telemetria normalizada, validação de dados faltantes, source attribution com NAT/proxies e análise longitudinal de falsos positivos.
