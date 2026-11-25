"""Regenerate the static project walkthrough diagrams (requires matplotlib)."""
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


OUT = Path(__file__).resolve().parent / "images"
OUT.mkdir(parents=True, exist_ok=True)

BG = "#f4f7fb"
INK = "#17263c"
MUTED = "#52647a"
BLUE = "#dcecff"
BLUE_EDGE = "#3878c8"
TEAL = "#d9f3ee"
TEAL_EDGE = "#238a79"
VIOLET = "#ece4ff"
VIOLET_EDGE = "#7652b5"
AMBER = "#fff0d0"
AMBER_EDGE = "#b87a14"
RED = "#ffe2e3"
RED_EDGE = "#b84550"
GRAY = "#e8edf4"
GRAY_EDGE = "#61758c"


def canvas(title, subtitle, figsize):
    fig, ax = plt.subplots(figsize=figsize)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(.04, .94, title, fontsize=22, fontweight="bold", color=INK, va="top")
    ax.text(.04, .875, subtitle, fontsize=10.5, color=MUTED, va="top")
    return fig, ax


def box(ax, x, y, w, h, label, fill=BLUE, edge=BLUE_EDGE, size=10, weight="normal"):
    patch = FancyBboxPatch(
        (x - w / 2, y - h / 2), w, h,
        boxstyle="round,pad=0.012,rounding_size=0.018",
        facecolor=fill, edgecolor=edge, linewidth=1.6, zorder=2,
    )
    ax.add_patch(patch)
    ax.text(x, y, label, ha="center", va="center", fontsize=size,
            color=INK, fontweight=weight, linespacing=1.25, zorder=3)


def arrow(ax, start, end, label=None, color=GRAY_EDGE, curve=0, style="-|>"):
    connection = f"arc3,rad={curve}"
    edge = FancyArrowPatch(
        start, end, arrowstyle=style, mutation_scale=14,
        linewidth=1.7, color=color, connectionstyle=connection,
        shrinkA=5, shrinkB=5, zorder=1,
    )
    ax.add_patch(edge)
    if label:
        midx, midy = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
        ax.text(midx, midy + .025, label, fontsize=8.5, color=MUTED,
                ha="center", va="bottom", bbox={"facecolor": BG, "edgecolor": "none", "pad": 1}, zorder=4)


def save(fig, filename):
    fig.savefig(OUT / filename, dpi=200, bbox_inches="tight", facecolor=BG)
    plt.close(fig)


def system_architecture():
    fig, ax = canvas(
        "MultiCloudSecurity | system architecture",
        "Selected cloud settings flow through one analysis pipeline; ML is advisory and uses collected posture evidence.",
        (15, 8),
    )
    centers = [.09, .25, .41, .57, .75, .92]
    labels = [
        "PROVIDERS\nAWS S3\nAzure Storage\nMeraki · Cloudflare",
        "CONNECTORS\nList resources\nRead selected settings",
        "SNAPSHOTS\nRaw provider JSON\nLocal data files",
        "NORMALIZERS\nShared posture fields\nEvidence dimensions",
        "ANALYSIS\nProvider rules\nWeighted risk · ML triage\nProject benchmarks",
        "DASHBOARD\nFindings · risk\nRemediation · reports",
    ]
    fills = [GRAY, BLUE, GRAY, TEAL, VIOLET, BLUE]
    edges = [GRAY_EDGE, BLUE_EDGE, GRAY_EDGE, TEAL_EDGE, VIOLET_EDGE, BLUE_EDGE]
    widths = [.14, .14, .14, .14, .19, .14]
    for x, label, fill, edge, width in zip(centers, labels, fills, edges, widths):
        box(ax, x, .66, width, .25, label, fill, edge, 9.1, "bold")
    for left, right in zip(centers, centers[1:]):
        arrow(ax, (left + .07, .66), (right - .07, .66))

    ax.text(.06, .36, "APPROVED CHANGE LOOP", fontsize=10, color=TEAL_EDGE, fontweight="bold")
    box(ax, .5, .22, .78, .17,
        "Admin review + WebAuthn approval   →   Provider API write or local demo simulation\n"
        "Fresh provider recollection   →   compare previous finding rules\n"
        "Current limitation: the verifier does not require complete post-fix evidence",
        AMBER, AMBER_EDGE, 9.2, "bold")
    ax.text(.06, .075, "Demo assets are fictional; live scans and writes require configured provider API credentials.", fontsize=9.2, color=MUTED)
    save(fig, "system_architecture.png")


def scan_methodology():
    fig, ax = canvas(
        "Scan methodology | from cloud state to findings",
        "A scan is a point-in-time API collection followed by local, deterministic analysis.",
        (10, 11),
    )
    yvals = [.79, .64, .49, .34, .19]
    nodes = [
        ("1  Select source", "Connected provider API or local demo/snapshot", GRAY, GRAY_EDGE),
        ("2  Collect settings", "Connector reads supported resources and fields;\nprovider errors may leave evidence incomplete", BLUE, BLUE_EDGE),
        ("3  Normalize evidence", "Provider fields → common dimensions +\nevaluated_dimensions", TEAL, TEAL_EDGE),
        ("4  Analyze", "Rules → findings   |   evaluated dimensions → weighted risk\nSame evidence → advisory ML risk band   |   map project benchmarks", VIOLET, VIOLET_EDGE),
        ("5  Save and display", "Timestamped JSON report + scan history →\nDashboard, Findings, Risk, Compliance, Reports", BLUE, BLUE_EDGE),
    ]
    for y, (head, desc, fill, edge) in zip(yvals, nodes):
        box(ax, .5, y, .72, .105, f"{head}\n{desc}", fill, edge, 10, "normal")
    for high, low in zip(yvals, yvals[1:]):
        arrow(ax, (.5, high - .057), (.5, low + .057))
    ax.text(.5, .075, "Unknown or unreadable settings should remain unevaluated; they are not proof of a secure configuration.",
            fontsize=9, ha="center", color=RED_EDGE,
            bbox={"boxstyle": "round,pad=.6", "facecolor": "#fff7f7", "edgecolor": RED_EDGE})
    save(fig, "scan_methodology.png")


def remediation_workflow():
    fig, ax = canvas(
        "Remediation | approval, change, and verification",
        "The UI separates fictional demo changes from real provider API writes.",
        (12, 9),
    )
    box(ax, .5, .79, .38, .11, "Finding with supported remediation", BLUE, BLUE_EDGE, 11, "bold")
    box(ax, .5, .62, .42, .13, "Administrator reviews impact and exact resource\nConfirms change and approves with WebAuthn", AMBER, AMBER_EDGE, 10, "bold")
    box(ax, .5, .44, .32, .10, "Is the resource marked DEMO?", GRAY, GRAY_EDGE, 10, "bold")
    box(ax, .25, .27, .34, .13, "DEMO PATH\nUpdate fictional local data\nNo provider API is called", TEAL, TEAL_EDGE, 9.5, "bold")
    box(ax, .75, .27, .36, .13, "LIVE PATH\nCall reviewed provider API\nRequires provider write permissions", AMBER, AMBER_EDGE, 9.5, "bold")
    box(ax, .5, .125, .53, .105, "Fresh provider recollection + analysis\nCurrent verifier checks whether prior rule IDs disappeared", VIOLET, VIOLET_EDGE, 9.2, "bold")
    arrow(ax, (.5, .735), (.5, .675))
    arrow(ax, (.5, .555), (.5, .495))
    arrow(ax, (.43, .39), (.29, .34), "yes")
    arrow(ax, (.57, .39), (.71, .34), "no")
    arrow(ax, (.32, .20), (.44, .18))
    arrow(ax, (.68, .20), (.56, .18))
    ax.text(.5, .045, "Limitation: complete post-fix evidence is not required by the verifier.",
            fontsize=8.6, ha="center", color=RED_EDGE)
    save(fig, "remediation_workflow.png")


def project_structure():
    fig, ax = canvas(
        "Project structure | where the work lives",
        "Top-level folders follow the scan lifecycle, from API collection through web presentation.",
        (14, 10),
    )
    ax.text(.06, .79,
            "MultiCloudSecurity2.0/\n"
            "├── connectors/                 # AWS, Azure, Meraki, Cloudflare collection\n"
            "│   ├── collect.py              # Provider selection + CLI collection\n"
            "│   └── provider_credentials.py # Local encrypted credential storage\n"
            "├── normalizer/                 # Provider data → shared posture + evidence\n"
            "├── security/                   # Four core provider finding rules + risk weights\n"
            "├── compliance/benchmarks/      # 12 project-level control mappings + evaluator\n"
            "├── ml/                         # Synthetic Naive Bayes training/model/evaluation\n"
            "├── remediation/                # Provider changes + manual config validation\n"
            "├── verification/               # Post-change finding comparison\n"
            "├── backend/security_pipeline.py# Analysis orchestration + JSON reports\n"
            "├── dashboard/                  # Flask app, authentication, pages, CSS, JS\n"
            "│   ├── templates/               # Dashboard and multi-page views\n"
            "│   └── auth.py                  # SQLite users, roles, audit, scan jobs\n"
            "├── examples/                   # 88 fictional demo resources + local simulations\n"
            "├── data/                       # Snapshots, reports, SQLite DB, demo data\n"
            "├── tests/                      # Unit/workflow tests (mostly fixtures/mocks)\n"
            "├── host.bat                    # Windows local launcher\n"
            "└── README.md                  # Setup, workflow, and limitations",
            fontfamily="DejaVu Sans Mono", fontsize=10.4, color=INK,
            va="top", linespacing=1.55,
            bbox={"boxstyle": "round,pad=.8", "facecolor": "white", "edgecolor": "#d2dce8"})
    save(fig, "project_structure.png")


if __name__ == "__main__":
    system_architecture()
    scan_methodology()
    remediation_workflow()
    project_structure()
    print(f"Generated diagrams in {OUT}")
