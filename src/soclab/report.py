"""Deterministic (relative-time) case reporting and evidence exports."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .telemetry import parse_timestamp


def write_report(events: list[dict[str, Any]], result: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    fields = ["event_id", "timestamp", "src_ip", "event_type", "result", "service", "principal", "qname", "dst_port"]
    sorted_events = sorted(events, key=lambda e: (parse_timestamp(e["timestamp"]), e["event_id"]))
    with (out / "timeline.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ev in sorted_events:
            writer.writerow(ev)
    cats = Counter(f["category"] for f in result["findings"])
    ids = {e["event_id"] for e in events}
    for finding in result["findings"] + result.get("correlations", []):
        if not set(finding["evidence_ids"]).issubset(ids):
            raise ValueError("evidence chain contains missing event ID")
    lines = [
        "# Relatório de investigação | Identity & Network Correlation Lab", "",
        "> Execução própria em loopback. Serviços e contas fictícios. Não é incidente corporativo.", "",
        "## Escopo e cadeia de evidências", "",
        f"- Eventos observados por serviços locais: **{len(events)}**",
        f"- Origens de teste distintas: **{len(result['sources'])}**",
        "- Fonte primária: `events.jsonl` (auditoria emitida pelos listeners)",
        "- Extração e ordenação: `timeline.csv`", "- Resultado determinístico sobre a mesma telemetria: `findings.json`", "",
        "## Resultado das detecções", "",
        "| Regra | Ocorrências |", "| --- | ---: |",
    ]
    lines.extend(f"| {cat} | {count} |" for cat, count in sorted(cats.items()))
    lines.extend(["", "## Correlação multissinal", ""])
    if not result.get("correlations"):
        lines.append("Nenhuma origem reuniu os três sinais dentro da janela configurada.")
    else:
        for item in result["correlations"]:
            lines.extend([
                f"- Origem: `{item['src_ip']}`", f"- Sinais: `{', '.join(item['signal_categories'])}`",
                f"- Evidências associadas: **{len(item['evidence_ids'])}** registros",
                f"- Interpretação: {item['assessment']}", "",
            ])
    lines.extend(["", "## Achados por origem", ""])
    for f in result["findings"]:
        lines.extend([
            f"### {f['category']} | {f['src_ip']}", "",
            f"- Técnica MITRE hipotética: `{f['mitre_technique']}`",
            f"- Janela: `{f['first_seen']}` a `{f['last_seen']}`",
            f"- Eventos: **{f['event_count']}**; valores distintos: **{f['distinct_values']}**",
            f"- Autenticações bem-sucedidas da mesma origem na janela: **{f['successful_auth_from_same_origin_in_window']}**",
            f"- Evidência rastreável: `{', '.join(f['evidence_ids'])}`", "",
            f"**Interpretação:** {f['conclusion']}", "",
        ])
    lines.extend([
        "## Avaliação", "",
        "A autenticação falha distribuída entre várias identidades e a atividade de descoberta",
        "exigem investigação. Nenhuma dessas evidências comprova uso de credenciais válidas",
        "por agente não autorizado, execução remota ou movimento lateral.", "",
        "A autenticação bem-sucedida de uma **outra origem** não pode ser vinculada ao host",
        "investigado apenas pela proximidade temporal.", "",
        "## Ações recomendadas no cenário", "",
        "1. Revisar histórico de autenticações por origem e principal; validar origem real e NAT.",
        "2. Correlacionar identidade/EDR com atividades de rede antes de inferir comprometimento.",
        "3. Verificar autorização de ferramentas de inventário e rotinas de autenticação.",
        "4. Confirmar com o responsável e seguir o fluxo de contenção baseado em criticidade.", "",
        "## Limitações", "",
        "- O serviço de identidade é **HTTP local**, não Active Directory/LDAP/NTLM/Kerberos.",
        "- O DNS PTR utiliza datagramas DNS reais, mas um responder mínimo restrito ao loopback.",
        "- TCP mostra conexões aceitas por serviços locais, não enumeração completa de portas fechadas.",
        "- Resultados não são métricas de precisão/recall em ambiente de produção.",
        "- Ausência de senha nos logs impede comprovar reutilização de uma mesma senha.",
        "- Sem contexto EDR/host, não é possível inferir execução remota.", "",
    ])
    (out / "case-report.md").write_text("\n".join(lines), encoding="utf-8")
