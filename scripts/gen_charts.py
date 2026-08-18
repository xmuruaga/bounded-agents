"""Generate evaluation charts for docs/evaluation.html."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs"

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['Inter', 'Helvetica Neue', 'Arial', 'sans-serif'],
    'font.size': 12,
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.spines.left': True,
    'axes.spines.bottom': True,
    'axes.linewidth': 0.6,
    'axes.edgecolor': '#cbd5e1',
    'xtick.color': '#64748b',
    'ytick.color': '#64748b',
    'axes.labelcolor': '#334155',
    'figure.facecolor': 'white',
    'axes.facecolor': 'white',
    'grid.color': '#e2e8f0',
    'grid.linewidth': 0.5,
})

# Colors
C_BASELINE = '#e8a87c'   # warm salmon
C_APC = '#2d3748'        # dark slate


def chart_composition_closure():
    """Static benchmark results: InjecAgent + ASB."""
    fig, ax = plt.subplots(figsize=(8, 4.5))

    categories = ['Data Stealing\n(InjecAgent)', 'Disruptive\n(ASB)',
                  'Direct Harm\n(InjecAgent)', 'Stealthy\n(ASB)']
    baseline = [100, 100, 100, 100]
    apc = [0, 0, 60.4, 30]

    x = np.arange(len(categories))
    w = 0.32

    bars1 = ax.bar(x - w/2, baseline, w, label='No defense', color=C_BASELINE,
                   edgecolor='white', linewidth=0.5)
    bars2 = ax.bar(x + w/2, apc, w, label='With APC', color=C_APC,
                   edgecolor='white', linewidth=0.5)

    # Value labels
    for bar, val in zip(bars1, baseline):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5,
                f'{val:.0f}%', ha='center', va='bottom', fontsize=10,
                color='#64748b', fontweight='500')
    for bar, val in zip(bars2, apc):
        y = max(val, 2)
        ax.text(bar.get_x() + bar.get_width()/2, y + 1.5,
                f'{val:.0f}%', ha='center', va='bottom', fontsize=10,
                color='#1e293b', fontweight='600')

    ax.set_ylabel('Attack Success Rate (%)', fontsize=11, fontweight='500')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10)
    ax.set_ylim(0, 115)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.yaxis.grid(True, alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.28),
              ncol=2, frameon=False, fontsize=10)

    plt.subplots_adjust(bottom=0.22)
    fig.savefig(OUT / 'chart-composition.svg', format='svg', bbox_inches='tight')
    fig.savefig(OUT / 'chart-composition.png', format='png', dpi=200, bbox_inches='tight')
    plt.close()
    print('Generated chart-composition.svg/png')


def chart_compromised_model():
    """Two separate charts: by domain and by attack type."""
    # Chart 1: ASR by domain
    fig1, ax1 = plt.subplots(figsize=(6, 4))
    suites = ['Workspace', 'Banking', 'Travel', 'Slack']
    no_defense = [77.5, 77.8, 88.3, 80.0]
    apc = [6.7, 1.4, 0.5, 0.5]  # visual min for 0%
    apc_actual = [6.7, 1.4, 0, 0]

    x = np.arange(len(suites))
    w = 0.32
    ax1.bar(x - w/2, no_defense, w, label='No defense', color=C_BASELINE, edgecolor='white', linewidth=0.5)
    ax1.bar(x + w/2, apc, w, label='With APC', color=C_APC, edgecolor='white', linewidth=0.5)

    for i, (nd, a) in enumerate(zip(no_defense, apc_actual)):
        ax1.text(x[i] - w/2, nd + 1.5, f'{nd:.0f}%', ha='center', va='bottom', fontsize=10, color='#64748b', fontweight='500')
        ax1.text(x[i] + w/2, max(a, 2) + 1.5, f'{a:.0f}%', ha='center', va='bottom', fontsize=10, color='#1e293b', fontweight='600')

    ax1.set_ylabel('Attack Success Rate (%)', fontsize=11, fontweight='500')
    ax1.set_xticks(x)
    ax1.set_xticklabels(suites, fontsize=11)
    ax1.set_ylim(0, 105)
    ax1.set_yticks([0, 25, 50, 75, 100])
    ax1.yaxis.grid(True, alpha=0.5)
    ax1.set_axisbelow(True)
    ax1.legend(loc='lower center', bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False, fontsize=10)
    plt.subplots_adjust(bottom=0.22)
    fig1.savefig(OUT / 'chart-compromised-domain.svg', format='svg', bbox_inches='tight')
    fig1.savefig(OUT / 'chart-compromised-domain.png', format='png', dpi=200, bbox_inches='tight')
    plt.close()
    print('Generated chart-compromised-domain.svg/png')

    # Chart 2: ASR by attack type (all suites combined, with APC)
    fig2, ax2 = plt.subplots(figsize=(6, 4))
    types = ['Exfiltration', 'Destruction', 'Manipulation']
    # Pooled no-defense across suites, using Table 8's row grouping:
    #   exfiltration    309/355 = 87.0%   (APC 0/355)
    #   destruction      39/101 = 38.6%   (APC 4/101 = 4.0%)
    #   manipulation    105/116 = 90.5%   (APC 14/116 = 12.1%)
    # Account takeover (16) and reconnaissance (21) are separate Table 8 rows
    # and are excluded here; 355 + 101 + 116 + 16 + 21 = 609.
    no_def_type = [87.0, 38.6, 90.5]
    apc_type = [0.5, 4.0, 12.1]  # visual min for 0%
    apc_type_actual = [0, 4.0, 12.1]

    x2 = np.arange(len(types))
    ax2.bar(x2 - w/2, no_def_type, w, label='No defense', color=C_BASELINE, edgecolor='white', linewidth=0.5)
    ax2.bar(x2 + w/2, apc_type, w, label='With APC', color=C_APC, edgecolor='white', linewidth=0.5)

    for i, (nd, a) in enumerate(zip(no_def_type, apc_type_actual)):
        ax2.text(x2[i] - w/2, nd + 1.5, f'{nd:.0f}%', ha='center', va='bottom', fontsize=10, color='#64748b', fontweight='500')
        ax2.text(x2[i] + w/2, max(a, 2) + 1.5, f'{a:.0f}%', ha='center', va='bottom', fontsize=10, color='#1e293b', fontweight='600')

    ax2.set_ylabel('Attack Success Rate (%)', fontsize=11, fontweight='500')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(types, fontsize=11)
    ax2.set_ylim(0, 105)
    ax2.set_yticks([0, 25, 50, 75, 100])
    ax2.yaxis.grid(True, alpha=0.5)
    ax2.set_axisbelow(True)
    ax2.legend(loc='lower center', bbox_to_anchor=(0.5, -0.22), ncol=2, frameon=False, fontsize=10)
    plt.subplots_adjust(bottom=0.22)
    fig2.savefig(OUT / 'chart-compromised-type.svg', format='svg', bbox_inches='tight')
    fig2.savefig(OUT / 'chart-compromised-type.png', format='png', dpi=200, bbox_inches='tight')
    plt.close()
    print('Generated chart-compromised-type.svg/png')


def chart_hero_summary():
    """Hero summary: single chart showing APC impact across all evaluation layers."""
    fig, ax = plt.subplots(figsize=(9, 4.5))

    categories = [
        'Exfiltration\n(4 domains)',
        'Destruction',
        'Manipulation',
        'Data Stealing\n(InjecAgent)',
        'Disruptive\n(ASB)',
        'Adaptive\nAttacks',
    ]
    no_defense = [87.0, 38.6, 90.5, 100, 100, 100]
    apc =        [0.5,  4.0,  12.1, 0.5, 0.5, 0.5]  # visual min
    apc_actual = [0,    4.0,  12.1, 0,   0,   0]

    x = np.arange(len(categories))
    w = 0.32

    ax.bar(x - w/2, no_defense, w, label='No defense', color=C_BASELINE,
           edgecolor='white', linewidth=0.5)
    ax.bar(x + w/2, apc, w, label='With APC', color=C_APC,
           edgecolor='white', linewidth=0.5)

    for i, (nd, a) in enumerate(zip(no_defense, apc_actual)):
        ax.text(x[i] - w/2, nd + 1.5, f'{nd:.0f}%', ha='center', va='bottom',
                fontsize=9, color='#64748b', fontweight='500')
        ax.text(x[i] + w/2, max(a, 2) + 1.5, f'{a:.0f}%', ha='center', va='bottom',
                fontsize=9, color='#1e293b', fontweight='600')

    # Divider between compromised-model and static benchmarks
    ax.axvline(x=2.5, color='#e2e8f0', linewidth=1, linestyle='--', alpha=0.7)
    ax.text(1, 108, 'Compromised-model (live LLM)', ha='center', fontsize=8,
            color='#94a3b8', style='italic')
    ax.text(4.5, 108, 'Static benchmarks', ha='center', fontsize=8,
            color='#94a3b8', style='italic')

    ax.set_ylabel('Attack Success Rate (%)', fontsize=11, fontweight='500')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9)
    ax.set_ylim(0, 115)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.yaxis.grid(True, alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.25),
              ncol=2, frameon=False, fontsize=10)

    plt.subplots_adjust(bottom=0.22)
    fig.savefig(OUT / 'chart-hero.svg', format='svg', bbox_inches='tight')
    fig.savefig(OUT / 'chart-hero.png', format='png', dpi=200, bbox_inches='tight')
    plt.close()
    print('Generated chart-hero.svg/png')


if __name__ == '__main__':
    chart_composition_closure()
    chart_compromised_model()
    chart_hero_summary()
    print('Done.')
