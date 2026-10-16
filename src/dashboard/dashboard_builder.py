"""Dashboard HTML statique (Plotly) présentant l'impact de la micro-segmentation
et sa validation sur capture réseau simulée."""
from __future__ import annotations

from src.evaluation.metrics import SegmentationComparison


def build_dashboard_html(comparison: SegmentationComparison, output_path: str) -> None:
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    pv = comparison.pcap_validation
    before_crit, after_crit = comparison.critical_direct_exposure_reduction

    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "bar"}, {"type": "bar"}], [{"type": "bar"}, {"type": "bar"}]],
        subplot_titles=(
            "Hôtes critiques directement exposés (avant/après)",
            "Nombre de règles de pare-feu",
            "Validation pcap -- mouvements latéraux bloqués",
            "Validation pcap -- continuité des flux métier",
        ),
        vertical_spacing=0.18,
    )

    fig.add_trace(
        go.Bar(x=["Avant (hérité)", "Après (adaptatif)"], y=[before_crit, after_crit],
               marker_color=["#B00020", "#2E7D32"], text=[before_crit, after_crit], textposition="outside"),
        row=1, col=1,
    )

    fig.add_trace(
        go.Bar(x=["Avant (hérité)", "Après (adaptatif)"],
               y=[len(comparison.legacy_rules), len(comparison.segmented_rules)],
               marker_color=["#5E35B1", "#00838F"],
               text=[len(comparison.legacy_rules), len(comparison.segmented_rules)], textposition="outside"),
        row=1, col=2,
    )

    n_blocked_after = pv.n_lateral_blocked_by_adaptive
    n_allowed_after = pv.n_lateral_movement_attempts - n_blocked_after
    fig.add_trace(
        go.Bar(x=["Réseau hérité", "Segmentation adaptative"],
               y=[pv.n_lateral_allowed_by_legacy, n_allowed_after],
               marker_color=["#B00020", "#2E7D32"],
               text=[f"{pv.n_lateral_allowed_by_legacy}/{pv.n_lateral_movement_attempts}",
                     f"{n_allowed_after}/{pv.n_lateral_movement_attempts}"],
               textposition="outside"),
        row=2, col=1,
    )

    fig.add_trace(
        go.Bar(x=["Flux légitimes préservés"], y=[pv.n_legit_flows_still_allowed_by_adaptive],
               marker_color=["#2E7D32"],
               text=[f"{pv.n_legit_flows_still_allowed_by_adaptive}/{pv.n_legit_flows_total}"], textposition="outside"),
        row=2, col=2,
    )

    fig.update_yaxes(title_text="Nombre d'hôtes", row=1, col=1)
    fig.update_yaxes(title_text="Nombre de règles", row=1, col=2)
    fig.update_yaxes(title_text="Mouvements latéraux autorisés", row=2, col=1)
    fig.update_yaxes(title_text="Flux légitimes", range=[0, pv.n_legit_flows_total + 5], row=2, col=2)

    fig.update_layout(
        title_text="Micro-segmentation Réseau Adaptative -- Validée sur capture réseau simulée (pcap)",
        height=800, showlegend=False, template="plotly_white",
    )

    fig.write_html(output_path, include_plotlyjs=True, full_html=True)
