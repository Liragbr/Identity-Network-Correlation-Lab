# Reprodução offline das evidências

`events.jsonl` foi coletado pelos serviços locais durante uma execução real do projeto, sem qualquer dado de cliente. `findings.json` e `case-report.md` são derivados desse arquivo.

Da raiz do projeto:

```bash
export PYTHONPATH=src
python3 -m soclab verify --events examples/events.jsonl --output artifacts/offline
```

Compare `artifacts/offline/findings.json` com `examples/findings.json`: os conteúdos devem ser iguais. As portas e timestamps nesta amostra representam **somente a execução de referência**, não infraestrutura corporativa.
