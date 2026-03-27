"""
dashboard/app.py — AutoRedTeam LLM Security Dashboard

Run from project root:
    streamlit run dashboard/app.py
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))
import config

# ── Page config ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="AutoRedTeam — LLM Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styling ────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    /* ── Base ── */
    html, body, [class*="css"] { font-family: 'Inter', 'Segoe UI', sans-serif; }
    .stApp { background-color: #0d1117; }
    section[data-testid="stSidebar"] { background-color: #161b27 !important; }

    /* ── Metric cards ── */
    .card {
        background: linear-gradient(135deg, #1c2333 0%, #212c3f 100%);
        border-radius: 14px;
        padding: 22px 26px 18px;
        border-left: 4px solid;
        height: 100%;
    }
    .card-red    { border-color: #ff4b4b; }
    .card-orange { border-color: #ffa94d; }
    .card-blue   { border-color: #4dabf7; }
    .card-green  { border-color: #51cf66; }
    .card-purple { border-color: #cc5de8; }

    .card-value {
        font-size: 2.4rem;
        font-weight: 700;
        color: #f1f3f5;
        line-height: 1.1;
        letter-spacing: -0.02em;
    }
    .card-label {
        font-size: 0.78rem;
        color: #6e7d96;
        margin-top: 5px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 500;
    }
    .card-sub {
        font-size: 0.82rem;
        color: #8899aa;
        margin-top: 3px;
    }

    /* ── Section headers ── */
    .sec-head {
        font-size: 1.05rem;
        font-weight: 600;
        color: #c9d1d9;
        margin: 20px 0 10px;
        padding-bottom: 6px;
        border-bottom: 1px solid #21293c;
        letter-spacing: 0.01em;
    }

    /* ── Page title ── */
    .page-title {
        font-size: 2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #4dabf7 0%, #cc5de8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        line-height: 1.2;
    }
    .page-sub {
        color: #6e7d96;
        font-size: 0.88rem;
        margin-top: 4px;
        margin-bottom: 20px;
    }

    /* ── Badges ── */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }
    .b-red    { background: rgba(255,75,75,0.18);  color: #ff6b6b; }
    .b-orange { background: rgba(255,169,77,0.18); color: #ffa94d; }
    .b-green  { background: rgba(81,207,102,0.18); color: #51cf66; }

    /* ── Sidebar branding ── */
    .brand-title {
        font-size: 1.25rem;
        font-weight: 700;
        color: #e6edf3;
        letter-spacing: -0.01em;
    }
    .brand-sub {
        font-size: 0.78rem;
        color: #6e7d96;
        margin-top: 2px;
    }
    .model-pill {
        display: inline-block;
        background: #21293c;
        color: #8899aa;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.76rem;
        margin: 2px 0;
    }

    /* ── Misc ── */
    hr { border-color: #21293c !important; margin: 10px 0; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    .stExpander { border: 1px solid #21293c !important; border-radius: 10px !important; }
</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────

MODEL_DISPLAY = {
    "llama":   "Llama 3.1 8B",
    "mistral": "Mistral 7B",
    "qwen":    "Qwen2.5 7B",
}
CAT_DISPLAY = {
    "jailbreak":        "Jailbreak",
    "pii_extraction":   "PII Extraction",
    "prompt_injection": "Prompt Injection",
}
LABEL_COLORS = {
    "VULNERABLE": "#ff4b4b",
    "PARTIAL":    "#ffa94d",
    "SAFE":       "#51cf66",
}
MODEL_COLORS = {
    "llama":   "#4dabf7",
    "mistral": "#cc5de8",
    "qwen":    "#ffa94d",
}
DEF_COLORS = {
    "Baseline":           "#ff6b6b",
    "Hardened Prompt":    "#51cf66",
    "Input Sanitization": "#4dabf7",
    "Combined":           "#cc5de8",
}
PLOTLY_BASE = dict(
    paper_bgcolor="#0d1117",
    plot_bgcolor="#161b27",
    font=dict(color="#c9d1d9", family="Inter, Segoe UI, sans-serif", size=12),
)

# ── Data loading ───────────────────────────────────────────────────────────────

@st.cache_data
def load_master() -> pd.DataFrame:
    """Load master_results.json; melt to long format (one row per model × prompt)."""
    path = config.RESULTS_DIR / "master_results.json"
    if not path.exists():
        return pd.DataFrame()
    raw = json.loads(path.read_text(encoding="utf-8"))
    models = list(config.MODELS.keys())
    rows = []
    for rec in raw:
        for model in models:
            lbl = rec.get(f"{model}_label")
            if lbl is None:
                continue
            rows.append({
                "prompt_id":    rec["prompt_id"],
                "category":     rec["category"],
                "subcategory":  rec.get("subcategory", ""),
                "technique":    rec.get("technique", "—"),
                "severity":     rec.get("severity", "—"),
                "prompt_text":  rec.get("prompt_text", ""),
                "model":        model,
                "response_text":    rec.get(f"{model}_response_text", ""),
                "label":            lbl,
                "confidence":       float(rec.get(f"{model}_confidence") or 0),
                "stage":            rec.get(f"{model}_classification_stage", ""),
                "guardrail_bypassed": rec.get(f"{model}_guardrail_bypassed", False),
            })
    return pd.DataFrame(rows)


@st.cache_data
def load_defense() -> pd.DataFrame:
    """Load defense_comparison.json."""
    path = config.DEFENSE_RESULTS_FILE
    if not path.exists():
        return pd.DataFrame()
    return pd.DataFrame(json.loads(path.read_text(encoding="utf-8")))


# ── Utility ────────────────────────────────────────────────────────────────────

def asr(d: pd.DataFrame) -> float:
    return 0.0 if d.empty else (d["label"] == "VULNERABLE").mean()


def card(value: str, label: str, accent: str, sub: str = "") -> str:
    sub_html = f'<div class="card-sub">{sub}</div>' if sub else ""
    return f"""
    <div class="card card-{accent}">
        <div class="card-value">{value}</div>
        <div class="card-label">{label}</div>
        {sub_html}
    </div>"""


def hex_to_rgba(hex_color: str, alpha: float = 0.15) -> str:
    """Convert a #rrggbb hex color to an rgba() string for Plotly."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def grid_axis(title: str = "") -> dict:
    return dict(gridcolor="#21293c", zerolinecolor="#21293c", title=title,
                tickfont=dict(color="#8899aa"))


# ── Sidebar ────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<div class="brand-title">🛡️ AutoRedTeam</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-sub">LLM Security Benchmark</div>', unsafe_allow_html=True)
    st.divider()

    page = st.radio(
        "Navigation",
        ["📊  Overview", "🔬  Model Deep Dive", "🛡️  Defense Analysis", "🔍  Attack Browser"],
        label_visibility="collapsed",
    )
    st.divider()

    st.markdown('<div class="card-label" style="margin-bottom:6px">Models tested</div>', unsafe_allow_html=True)
    for k, v in MODEL_DISPLAY.items():
        st.markdown(f'<div class="model-pill">● {v}</div>', unsafe_allow_html=True)

    st.divider()
    st.markdown('<div class="card-label">Attack categories</div>', unsafe_allow_html=True)
    for v in CAT_DISPLAY.values():
        st.markdown(f'<div style="color:#6e7d96;font-size:0.8rem;padding:2px 0">• {v}</div>', unsafe_allow_html=True)

# ── Load ───────────────────────────────────────────────────────────────────────

df = load_master()
defense_df = load_defense()

MODELS_LIST = ["llama", "mistral", "qwen"]
CATS_LIST   = ["jailbreak", "pii_extraction", "prompt_injection"]

# ══════════════════════════════════════════════════════════════════════════════
#  PAGE 1 — Overview
# ══════════════════════════════════════════════════════════════════════════════

if page == "📊  Overview":
    st.markdown('<div class="page-title">Security Overview</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="page-sub">Automated red-team benchmark · '
        '3 open-source LLMs · 150 attack prompts · 3 attack categories</div>',
        unsafe_allow_html=True,
    )

    # ── Top metrics ──
    total   = len(df)
    n_vuln  = (df["label"] == "VULNERABLE").sum()
    n_part  = (df["label"] == "PARTIAL").sum()
    n_safe  = (df["label"] == "SAFE").sum()
    overall = asr(df)
    avg_conf = df.loc[df["label"] == "VULNERABLE", "confidence"].mean() if n_vuln > 0 else 0.0

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: st.markdown(card(f"{total:,}", "Total Evaluations", "blue"), unsafe_allow_html=True)
    with c2: st.markdown(card(f"{n_vuln:,}", "Vulnerable", "red",   f"{n_vuln/total:.0%} of total"), unsafe_allow_html=True)
    with c3: st.markdown(card(f"{n_part:,}", "Partial",    "orange", f"{n_part/total:.0%} of total"), unsafe_allow_html=True)
    with c4: st.markdown(card(f"{n_safe:,}", "Safe",       "green",  f"{n_safe/total:.0%} of total"), unsafe_allow_html=True)
    with c5: st.markdown(card(f"{overall:.0%}", "Overall ASR", "purple", f"avg conf {avg_conf:.2f}"), unsafe_allow_html=True)

    st.divider()

    # ── Heatmap + donut ──
    col_heat, col_pie = st.columns([3, 2])

    with col_heat:
        st.markdown('<div class="sec-head">Attack Success Rate — Model × Category</div>', unsafe_allow_html=True)

        z, z_text = [], []
        for model in MODELS_LIST:
            row_z, row_t = [], []
            for cat in CATS_LIST:
                val = asr(df[(df["model"] == model) & (df["category"] == cat)]) * 100
                row_z.append(round(val, 1))
                row_t.append(f"{val:.0f}%")
            z.append(row_z)
            z_text.append(row_t)

        fig_heat = go.Figure(go.Heatmap(
            z=z,
            x=[CAT_DISPLAY[c] for c in CATS_LIST],
            y=[MODEL_DISPLAY[m] for m in MODELS_LIST],
            text=z_text,
            texttemplate="%{text}",
            textfont=dict(size=18, color="white", family="Inter, sans-serif"),
            colorscale=[
                [0.00, "#0d2818"],
                [0.40, "#7d4e00"],
                [0.70, "#cc2200"],
                [1.00, "#ff0000"],
            ],
            zmin=0, zmax=100,
            showscale=True,
            colorbar=dict(
                ticksuffix="%",
                tickfont=dict(color="#8899aa"),
                title=dict(text="ASR %", font=dict(color="#8899aa", size=11)),
            ),
        ))
        fig_heat.update_layout(
            **PLOTLY_BASE,
            height=280,
            margin=dict(l=0, r=10, t=10, b=0),
            xaxis=dict(side="bottom", tickfont=dict(size=13, color="#c9d1d9"), gridcolor="#21293c"),
            yaxis=dict(tickfont=dict(size=13, color="#c9d1d9"), gridcolor="#21293c"),
        )
        st.plotly_chart(fig_heat, width='stretch')

    with col_pie:
        st.markdown('<div class="sec-head">Response Label Distribution</div>', unsafe_allow_html=True)

        counts = df["label"].value_counts().reindex(["VULNERABLE", "PARTIAL", "SAFE"], fill_value=0)
        fig_pie = go.Figure(go.Pie(
            labels=counts.index.tolist(),
            values=counts.values.tolist(),
            hole=0.62,
            marker=dict(
                colors=[LABEL_COLORS[l] for l in counts.index],
                line=dict(color="#0d1117", width=3),
            ),
            textinfo="percent+label",
            textfont=dict(size=12, color="white"),
            pull=[0.04, 0, 0],
        ))
        fig_pie.update_layout(
            **PLOTLY_BASE,
            height=280,
            margin=dict(l=0, r=0, t=10, b=0),
            showlegend=False,
            annotations=[dict(
                text=f"<b>{overall:.0%}</b><br><span style='font-size:11px;color:#6e7d96'>Overall<br>ASR</span>",
                x=0.5, y=0.5, showarrow=False,
                font=dict(color="#f1f3f5", size=22),
            )],
        )
        st.plotly_chart(fig_pie, width='stretch')

    st.divider()

    # ── Grouped bar: ASR by model × category ──
    st.markdown('<div class="sec-head">ASR Breakdown by Model and Category</div>', unsafe_allow_html=True)

    bar_rows = []
    for model in MODELS_LIST:
        for cat in CATS_LIST:
            bar_rows.append({
                "Model":    MODEL_DISPLAY[model],
                "Category": CAT_DISPLAY[cat],
                "ASR":      round(asr(df[(df["model"] == model) & (df["category"] == cat)]) * 100, 1),
                "_color":   MODEL_COLORS[model],
            })
    bar_df = pd.DataFrame(bar_rows)

    fig_bar = px.bar(
        bar_df, x="Category", y="ASR", color="Model", barmode="group",
        color_discrete_map={MODEL_DISPLAY[m]: MODEL_COLORS[m] for m in MODELS_LIST},
        text="ASR",
    )
    fig_bar.update_traces(texttemplate="%{text:.0f}%", textposition="outside",
                          textfont=dict(size=11), marker_line_width=0)
    fig_bar.update_layout(
        **PLOTLY_BASE,
        height=380,
        margin=dict(l=0, r=10, t=20, b=0),
        yaxis=dict(**grid_axis("ASR (%)"), range=[0, 118], ticksuffix="%"),
        xaxis=dict(gridcolor="#21293c", tickfont=dict(size=13, color="#c9d1d9")),
        legend=dict(orientation="h", yanchor="bottom", y=1.02,
                    xanchor="right", x=1, bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#c9d1d9")),
        bargap=0.18, bargroupgap=0.05,
    )
    st.plotly_chart(fig_bar, width='stretch')

    # ── Radar chart comparing models ──
    st.markdown('<div class="sec-head">Model Vulnerability Profile</div>', unsafe_allow_html=True)

    fig_radar = go.Figure()
    theta = [CAT_DISPLAY[c] for c in CATS_LIST] + [CAT_DISPLAY[CATS_LIST[0]]]

    for model in MODELS_LIST:
        r_vals = [asr(df[(df["model"] == model) & (df["category"] == c)]) * 100 for c in CATS_LIST]
        r_vals.append(r_vals[0])
        fig_radar.add_trace(go.Scatterpolar(
            r=r_vals, theta=theta, fill="toself", name=MODEL_DISPLAY[model],
            line=dict(color=MODEL_COLORS[model], width=2),
            fillcolor=hex_to_rgba(MODEL_COLORS[model], 0.15),
        ))
    fig_radar.update_layout(
        **PLOTLY_BASE,
        height=380,
        polar=dict(
            bgcolor="#161b27",
            radialaxis=dict(visible=True, range=[0, 100], ticksuffix="%",
                            gridcolor="#21293c", tickfont=dict(color="#6e7d96", size=10)),
            angularaxis=dict(tickfont=dict(color="#c9d1d9", size=13), gridcolor="#21293c"),
        ),
        legend=dict(orientation="h", yanchor="bottom", y=-0.15,
                    xanchor="center", x=0.5, bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#c9d1d9")),
        margin=dict(l=40, r=40, t=20, b=40),
    )
    st.plotly_chart(fig_radar, width='stretch')


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE 2 — Model Deep Dive
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🔬  Model Deep Dive":
    st.markdown('<div class="page-title">Model Deep Dive</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-sub">Drill into per-model vulnerability patterns, technique effectiveness, and severity distribution</div>', unsafe_allow_html=True)

    model_key = st.selectbox(
        "Select model",
        options=MODELS_LIST,
        format_func=lambda k: MODEL_DISPLAY[k],
    )
    mdf = df[df["model"] == model_key]
    mc  = MODEL_COLORS[model_key]

    # ── Per-category metrics ──
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(card(f"{asr(mdf):.0%}", "Overall ASR", "red"), unsafe_allow_html=True)
    for i, cat in enumerate(CATS_LIST):
        sub = mdf[mdf["category"] == cat]
        v = asr(sub)
        acc = "red" if v > 0.85 else "orange" if v > 0.6 else "green"
        with [c2, c3, c4][i]:
            st.markdown(card(f"{v:.0%}", CAT_DISPLAY[cat], acc,
                             f"{(sub['label']=='VULNERABLE').sum()} / {len(sub)} attacks"),
                        unsafe_allow_html=True)

    st.divider()
    col_l, col_r = st.columns([3, 2])

    with col_l:
        st.markdown('<div class="sec-head">Jailbreak Technique Effectiveness</div>', unsafe_allow_html=True)

        tech_df = (
            mdf[mdf["category"] == "jailbreak"]
            .groupby("technique")
            .agg(asr_val=("label", lambda x: (x == "VULNERABLE").mean() * 100),
                 count=("label", "count"))
            .reset_index()
            .sort_values("asr_val", ascending=True)
        )
        if not tech_df.empty:
            fig_tech = px.bar(
                tech_df, x="asr_val", y="technique", orientation="h",
                color="asr_val",
                color_continuous_scale=["#1a3a1a", "#e67e22", "#e74c3c"],
                range_color=[0, 100],
                text="asr_val",
                hover_data={"count": True, "asr_val": ":.1f"},
                labels={"asr_val": "ASR (%)", "technique": "", "count": "Prompts"},
            )
            fig_tech.update_traces(
                texttemplate="%{text:.0f}%", textposition="outside",
                textfont=dict(size=11), marker_line_width=0,
            )
            fig_tech.update_layout(
                **PLOTLY_BASE,
                height=480,
                margin=dict(l=0, r=50, t=10, b=0),
                xaxis=dict(**grid_axis("ASR (%)"), range=[0, 118], ticksuffix="%"),
                yaxis=dict(gridcolor="#21293c", tickfont=dict(size=11, color="#c9d1d9")),
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_tech, width='stretch')

    with col_r:
        st.markdown('<div class="sec-head">Label Breakdown</div>', unsafe_allow_html=True)
        counts = mdf["label"].value_counts().reindex(["VULNERABLE", "PARTIAL", "SAFE"], fill_value=0)
        fig_donut = go.Figure(go.Pie(
            labels=counts.index.tolist(),
            values=counts.values.tolist(),
            hole=0.62,
            marker=dict(colors=[LABEL_COLORS[l] for l in counts.index],
                        line=dict(color="#0d1117", width=3)),
            textinfo="percent+label",
            textfont=dict(size=12, color="white"),
            pull=[0.04, 0, 0],
        ))
        fig_donut.update_layout(
            **PLOTLY_BASE,
            height=260,
            margin=dict(l=0, r=0, t=10, b=0),
            showlegend=False,
            annotations=[dict(
                text=f"<b>{asr(mdf):.0%}</b><br><span>ASR</span>",
                x=0.5, y=0.5, showarrow=False,
                font=dict(color="#f1f3f5", size=20),
            )],
        )
        st.plotly_chart(fig_donut, width='stretch')

        st.markdown('<div class="sec-head">Severity of Successful Attacks</div>', unsafe_allow_html=True)
        sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sev_colors_map = {"critical": "#ff0000", "high": "#ff4b4b", "medium": "#ffa94d", "low": "#51cf66"}
        sev_df = (
            mdf[mdf["label"] == "VULNERABLE"]["severity"]
            .value_counts()
            .reset_index()
            .rename(columns={"index": "Severity", "severity": "Count", "count": "Count"})
        )
        sev_df.columns = ["Severity", "Count"]
        sev_df["order"] = sev_df["Severity"].map(lambda s: sev_map.get(s, 99))
        sev_df = sev_df.sort_values("order")

        if not sev_df.empty:
            fig_sev = px.bar(
                sev_df, x="Count", y="Severity", orientation="h",
                color="Severity",
                color_discrete_map=sev_colors_map,
                text="Count",
            )
            fig_sev.update_traces(textposition="outside", marker_line_width=0)
            fig_sev.update_layout(
                **PLOTLY_BASE,
                height=200,
                margin=dict(l=0, r=40, t=10, b=0),
                showlegend=False,
                xaxis=dict(**grid_axis("Count")),
                yaxis=dict(gridcolor="#21293c", tickfont=dict(color="#c9d1d9")),
            )
            st.plotly_chart(fig_sev, width='stretch')

    # ── Confidence distribution ──
    st.divider()
    st.markdown('<div class="sec-head">Classifier Confidence by Label & Stage</div>', unsafe_allow_html=True)

    conf_df = mdf[["label", "stage", "confidence"]].copy()
    conf_df["confidence"] = conf_df["confidence"].clip(upper=1.0)

    stage_colors = {"rule_based": "#4dabf7", "embedding": "#ffa94d"}

    fig_conf = go.Figure()
    for stage, s_color in stage_colors.items():
        for lbl in ["VULNERABLE", "PARTIAL", "SAFE"]:
            sub = conf_df[(conf_df["label"] == lbl) & (conf_df["stage"] == stage)]
            if sub.empty:
                continue
            jitter = np.random.uniform(-0.18, 0.18, size=len(sub))
            y_pos  = {"VULNERABLE": 2, "PARTIAL": 1, "SAFE": 0}[lbl]
            fig_conf.add_trace(go.Scatter(
                x=sub["confidence"],
                y=y_pos + jitter,
                mode="markers",
                name=stage.replace("_", " ").title(),
                legendgroup=stage,
                showlegend=(lbl == "VULNERABLE"),
                marker=dict(
                    color=s_color,
                    size=7,
                    opacity=0.65,
                    line=dict(width=0),
                ),
                hovertemplate=f"<b>{lbl}</b><br>Stage: {stage}<br>Confidence: %{{x:.3f}}<extra></extra>",
            ))

    fig_conf.update_layout(
        **PLOTLY_BASE,
        height=280,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(**grid_axis("Confidence Score"), range=[0.5, 1.05]),
        yaxis=dict(
            tickvals=[0, 1, 2],
            ticktext=["SAFE", "PARTIAL", "VULNERABLE"],
            tickfont=dict(color="#c9d1d9", size=12),
            gridcolor="#21293c",
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02,
            xanchor="right", x=1,
            bgcolor="rgba(0,0,0,0)", font=dict(color="#c9d1d9"),
        ),
    )
    st.plotly_chart(fig_conf, width='stretch')

    # ── Top 10 attacks table ──
    st.divider()
    st.markdown('<div class="sec-head">Top 10 Highest-Confidence Successful Attacks</div>', unsafe_allow_html=True)

    top10 = (
        mdf[mdf["label"] == "VULNERABLE"]
        .sort_values("confidence", ascending=False)
        .head(10)[["prompt_id", "category", "technique", "severity", "confidence", "prompt_text"]]
        .reset_index(drop=True)
    )
    top10["confidence"] = top10["confidence"].map(lambda x: f"{x:.3f}")
    top10["prompt_text"] = top10["prompt_text"].str[:100] + "…"
    top10.columns = ["ID", "Category", "Technique", "Severity", "Confidence", "Prompt (truncated)"]
    top10["Category"] = top10["Category"].map(CAT_DISPLAY)
    st.dataframe(top10, width='stretch', hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE 3 — Defense Analysis
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🛡️  Defense Analysis":
    st.markdown('<div class="page-title">Defense Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-sub">Comparing three prompt-level defenses · DRR = (Baseline ASR − Defended ASR) / Baseline ASR</div>',
                unsafe_allow_html=True)

    if defense_df.empty:
        st.warning("No defense comparison data found. Run `defense_module.py` first.")
    else:
        sel_model = st.selectbox(
            "Filter by model",
            options=["All Models"] + MODELS_LIST,
            format_func=lambda k: k if k == "All Models" else MODEL_DISPLAY.get(k, k),
        )
        cat_filter = st.selectbox(
            "Filter by category",
            options=["All Categories"] + CATS_LIST,
            format_func=lambda k: k if k == "All Categories" else CAT_DISPLAY.get(k, k),
        )

        plot_src = defense_df[defense_df["category"] != "overall"].copy()
        if sel_model != "All Models":
            plot_src = plot_src[plot_src["model"] == sel_model]
        if cat_filter != "All Categories":
            plot_src = plot_src[plot_src["category"] == cat_filter]

        # ── Grouped bar: ASR by defense ──
        st.markdown('<div class="sec-head">ASR Before vs After Each Defense</div>', unsafe_allow_html=True)

        melt_rows = []
        for _, row in plot_src.iterrows():
            label = (
                CAT_DISPLAY.get(row["category"], row["category"])
                if sel_model != "All Models"
                else f"{MODEL_DISPLAY.get(row['model'], row['model'])} · {CAT_DISPLAY.get(row['category'], row['category'])}"
            )
            melt_rows.append({"Group": label, "Defense": "Baseline",           "ASR": row["baseline_asr"] * 100})
            melt_rows.append({"Group": label, "Defense": "Hardened Prompt",    "ASR": row["hardened_prompt_asr"] * 100})
            melt_rows.append({"Group": label, "Defense": "Input Sanitization", "ASR": row["input_sanitization_asr"] * 100})
            combined = row.get("combined_asr")
            if combined is not None and not (isinstance(combined, float) and pd.isna(combined)):
                melt_rows.append({"Group": label, "Defense": "Combined", "ASR": combined * 100})

        melt_df = pd.DataFrame(melt_rows)
        fig_def = px.bar(
            melt_df, x="Group", y="ASR", color="Defense", barmode="group",
            color_discrete_map=DEF_COLORS, text="ASR",
            labels={"ASR": "ASR (%)", "Group": "", "Defense": ""},
        )
        fig_def.update_traces(texttemplate="%{text:.0f}%", textposition="outside",
                              textfont=dict(size=10), marker_line_width=0)
        fig_def.update_layout(
            **PLOTLY_BASE,
            height=440,
            margin=dict(l=0, r=10, t=30, b=0),
            yaxis=dict(**grid_axis("ASR (%)"), range=[0, 118], ticksuffix="%"),
            xaxis=dict(gridcolor="#21293c", tickfont=dict(size=11, color="#c9d1d9"),
                       tickangle=-25 if sel_model == "All Models" else 0),
            legend=dict(orientation="h", yanchor="bottom", y=1.02,
                        xanchor="right", x=1, bgcolor="rgba(0,0,0,0)",
                        font=dict(color="#c9d1d9")),
            bargap=0.12, bargroupgap=0.04,
        )
        st.plotly_chart(fig_def, width='stretch')

        st.divider()
        col_drr_heat, col_drr_summary = st.columns([3, 2])

        with col_drr_heat:
            st.markdown('<div class="sec-head">DRR Heatmap — Model × Defense</div>', unsafe_allow_html=True)

            overall_src = defense_df[defense_df["category"] == "overall"]
            drr_defenses = [
                ("hardened_prompt",    "Hardened Prompt"),
                ("input_sanitization", "Input Sanitization"),
                ("combined",           "Combined"),
            ]
            drr_z, drr_text, drr_y = [], [], []
            for _, row in overall_src.iterrows():
                row_z, row_t = [], []
                for d_key, _ in drr_defenses:
                    val = row.get(f"{d_key}_reduction")
                    if val is None or (isinstance(val, float) and pd.isna(val)):
                        row_z.append(None)
                        row_t.append("—")
                    else:
                        row_z.append(round(val * 100, 1))
                        row_t.append(f"{val:.0%}")
                drr_z.append(row_z)
                drr_text.append(row_t)
                drr_y.append(MODEL_DISPLAY.get(row["model"], row["model"]))

            fig_drr = go.Figure(go.Heatmap(
                z=drr_z,
                x=[d[1] for d in drr_defenses],
                y=drr_y,
                text=drr_text,
                texttemplate="%{text}",
                textfont=dict(size=17, color="white"),
                colorscale=[
                    [0.0,  "#3a0a0a"],
                    [0.25, "#1a1a3a"],
                    [0.5,  "#0a2a3a"],
                    [0.75, "#0a3a2a"],
                    [1.0,  "#26de81"],
                ],
                zmin=-5, zmax=30,
                colorbar=dict(
                    ticksuffix="%",
                    tickfont=dict(color="#8899aa"),
                    title=dict(text="DRR %", font=dict(color="#8899aa", size=11)),
                ),
            ))
            fig_drr.update_layout(
                **PLOTLY_BASE,
                height=260,
                margin=dict(l=0, r=10, t=10, b=0),
                xaxis=dict(tickfont=dict(size=12, color="#c9d1d9"), gridcolor="#21293c"),
                yaxis=dict(tickfont=dict(size=12, color="#c9d1d9"), gridcolor="#21293c"),
            )
            st.plotly_chart(fig_drr, width='stretch')

        with col_drr_summary:
            st.markdown('<div class="sec-head">Overall DRR Summary</div>', unsafe_allow_html=True)

            overall_src2 = defense_df[defense_df["category"] == "overall"]
            rows = []
            for _, r in overall_src2.iterrows():
                def fmt_drr(key):
                    val = r.get(f"{key}_reduction")
                    if val is None or (isinstance(val, float) and pd.isna(val)):
                        return "—"
                    color = "#51cf66" if val > 0.1 else "#ffa94d" if val > 0 else "#ff4b4b"
                    return f'<span style="color:{color};font-weight:600">{val:.0%}</span>'

                rows.append({
                    "Model":      MODEL_DISPLAY.get(r["model"], r["model"]),
                    "Baseline":   f"{r['baseline_asr']:.0%}",
                    "H.Prompt ↓": fmt_drr("hardened_prompt"),
                    "Input S. ↓": fmt_drr("input_sanitization"),
                    "Combined ↓": fmt_drr("combined"),
                })
            st.markdown(
                pd.DataFrame(rows).to_html(escape=False, index=False,
                    classes="dataframe", border=0),
                unsafe_allow_html=True,
            )

        # ── Per-category DRR bar chart ──
        st.divider()
        st.markdown('<div class="sec-head">DRR by Category</div>', unsafe_allow_html=True)

        cat_drr_rows = []
        for _, row in defense_df[defense_df["category"] != "overall"].iterrows():
            for d_key, d_label in [
                ("hardened_prompt",    "Hardened Prompt"),
                ("input_sanitization", "Input Sanitization"),
                ("combined",           "Combined"),
            ]:
                val = row.get(f"{d_key}_reduction")
                if val is not None and not (isinstance(val, float) and pd.isna(val)):
                    cat_drr_rows.append({
                        "Model":    MODEL_DISPLAY.get(row["model"], row["model"]),
                        "Category": CAT_DISPLAY.get(row["category"], row["category"]),
                        "Defense":  d_label,
                        "DRR":      round(val * 100, 1),
                    })

        if cat_drr_rows:
            cdrr_df = pd.DataFrame(cat_drr_rows)
            if sel_model != "All Models":
                cdrr_df = cdrr_df[cdrr_df["Model"] == MODEL_DISPLAY[sel_model]]

            fig_cdrr = px.bar(
                cdrr_df, x="Category", y="DRR", color="Defense", barmode="group",
                facet_col="Model" if sel_model == "All Models" else None,
                color_discrete_map={k: v for k, v in DEF_COLORS.items() if k != "Baseline"},
                text="DRR",
                labels={"DRR": "DRR (%)", "Category": "", "Defense": ""},
            )
            fig_cdrr.update_traces(texttemplate="%{text:.0f}%", textposition="outside",
                                   textfont=dict(size=10), marker_line_width=0)
            fig_cdrr.update_layout(
                **PLOTLY_BASE,
                height=360,
                margin=dict(l=0, r=10, t=40, b=0),
                yaxis=dict(**grid_axis("DRR (%)"), ticksuffix="%"),
                xaxis=dict(gridcolor="#21293c", tickfont=dict(color="#c9d1d9")),
                legend=dict(orientation="h", yanchor="bottom", y=1.02,
                            xanchor="right", x=1, bgcolor="rgba(0,0,0,0)",
                            font=dict(color="#c9d1d9")),
                bargap=0.15,
            )
            if sel_model == "All Models":
                fig_cdrr.for_each_annotation(lambda a: a.update(text=a.text.split("=")[-1]))
            st.plotly_chart(fig_cdrr, width='stretch')


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE 4 — Attack Browser
# ══════════════════════════════════════════════════════════════════════════════

elif page == "🔍  Attack Browser":
    st.markdown('<div class="page-title">Attack Browser</div>', unsafe_allow_html=True)
    st.markdown('<div class="page-sub">Browse, search, and inspect all attack prompts and model responses</div>',
                unsafe_allow_html=True)

    fc1, fc2, fc3, fc4, fc5 = st.columns([1.2, 1.2, 1, 1, 2])
    with fc1:
        f_model = st.selectbox("Model", ["All"] + MODELS_LIST,
                               format_func=lambda k: "All Models" if k == "All" else MODEL_DISPLAY.get(k, k))
    with fc2:
        f_cat = st.selectbox("Category", ["All"] + CATS_LIST,
                             format_func=lambda k: "All Categories" if k == "All" else CAT_DISPLAY.get(k, k))
    with fc3:
        f_label = st.selectbox("Label", ["All", "VULNERABLE", "PARTIAL", "SAFE"])
    with fc4:
        f_sev = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with fc5:
        f_search = st.text_input("Search in prompt text", placeholder="keyword…")

    filt = df.copy()
    if f_model  != "All":          filt = filt[filt["model"]    == f_model]
    if f_cat    != "All":          filt = filt[filt["category"] == f_cat]
    if f_label  != "All":          filt = filt[filt["label"]    == f_label]
    if f_sev    != "All":          filt = filt[filt["severity"] == f_sev]
    if f_search.strip():           filt = filt[filt["prompt_text"].str.contains(f_search, case=False, na=False)]

    n_filt = len(filt)
    vuln_pct = (filt["label"] == "VULNERABLE").mean() if n_filt > 0 else 0
    st.markdown(
        f'<div style="color:#6e7d96;font-size:0.85rem;margin-bottom:8px">'
        f'Showing <b style="color:#c9d1d9">{n_filt:,}</b> results '
        f'— <span style="color:#ff4b4b">{vuln_pct:.0%} vulnerable</span></div>',
        unsafe_allow_html=True,
    )
    st.divider()

    PAGE_SIZE = 15
    total_pages = max(1, (n_filt - 1) // PAGE_SIZE + 1)

    if total_pages > 1:
        pg = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1,
                             label_visibility="collapsed")
        st.caption(f"Page {pg} of {total_pages}")
    else:
        pg = 1

    page_data = filt.iloc[(pg - 1) * PAGE_SIZE : pg * PAGE_SIZE].reset_index(drop=True)

    for _, row in page_data.iterrows():
        badge_cls   = {"VULNERABLE": "b-red", "PARTIAL": "b-orange", "SAFE": "b-green"}.get(row["label"], "")
        header_line = (
            f"[{row['prompt_id']}]  {MODEL_DISPLAY.get(row['model'], row['model'])}  ·  "
            f"{CAT_DISPLAY.get(row['category'], row['category'])}  ·  "
            f"{row['label']}  ·  conf {row['confidence']:.3f}"
        )
        with st.expander(header_line):
            meta_cols = st.columns(4)
            meta_cols[0].markdown(f"**Technique**\n\n`{row.get('technique', '—')}`")
            meta_cols[1].markdown(f"**Severity**\n\n`{row.get('severity', '—')}`")
            meta_cols[2].markdown(f"**Stage**\n\n`{row.get('stage', '—')}`")
            meta_cols[3].markdown(
                f"**Label**\n\n"
                f"<span class='badge {badge_cls}'>{row['label']}</span>",
                unsafe_allow_html=True,
            )
            st.divider()
            p_col, r_col = st.columns(2)
            with p_col:
                st.markdown("**Prompt**")
                st.code(row["prompt_text"], language=None)
            with r_col:
                st.markdown("**Model Response**")
                resp = row["response_text"]
                st.code((resp[:1000] + "\n… [truncated]") if len(resp) > 1000 else resp, language=None)
