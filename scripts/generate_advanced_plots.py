import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os
import shutil

# Set styling
# User palette: #473472, #53629E, #87BAC3, #D6F4ED
COLORS = ['#473472', '#53629E', '#87BAC3', '#D6F4ED']
sns.set_theme(style="whitegrid")
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Inter', 'Roboto', 'Arial']

# Directories
OUTPUT_DIR = 'research'
ARTIFACT_DIR = '/Users/maurya.pg13/.gemini/antigravity/brain/98a69d89-5866-4d14-a012-9e73c7724757/artifacts'

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_DIR, exist_ok=True)

def generate_security_time_budget():
    """Generates a pie chart breaking down the overhead of a secured request."""
    # Representative Synthetic Data based on AES-GCM and Bcrypt typical times
    labels = ['Network RTT', 'Bcrypt Hash (Work Factor 12)', 'TOTP Verification', 'AES-GCM Decryption']
    times_ms = [45.0, 75.0, 15.0, 1.5]
    
    # Explode the smallest piece (AES-GCM) to highlight efficiency
    explode = (0.05, 0.05, 0.05, 0.2)
    
    fig, ax = plt.subplots(figsize=(8, 8))
    
    # Custom colors mapping
    pie_colors = [COLORS[1], COLORS[0], COLORS[2], COLORS[3]]
    
    wedges, texts, autotexts = ax.pie(
        times_ms, 
        labels=labels, 
        autopct='%1.1f%%',
        startangle=140,
        colors=pie_colors,
        explode=explode,
        shadow=True,
        wedgeprops={'edgecolor': 'black', 'linewidth': 1.5},
        textprops={'fontsize': 12, 'fontweight': 'bold'}
    )
    
    plt.setp(autotexts, size=11, weight="bold", color="white")
    # Make the AES text dark since the color is very light (D6F4ED)
    autotexts[3].set_color("black")
    
    plt.title("Security Time Budget: Authentication & Processing Overhead", fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    
    out_file = os.path.join(OUTPUT_DIR, 'security_time_budget.png')
    plt.savefig(out_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    shutil.copy(out_file, os.path.join(ARTIFACT_DIR, 'security_time_budget.png'))
    print(f"Saved {out_file}")

def generate_throughput_decay():
    """Generates a line graph showing Throughput vs Payload Size for Baseline vs Secured."""
    # Synthetic mock data
    payload_sizes_kb = np.array([1, 10, 50, 100, 250, 500, 1000])
    
    # Baseline degrades steadily
    baseline_tps = np.array([850, 800, 650, 500, 300, 150, 80])
    
    # Secured has a small overhead initially, but holds up relatively well due to AES hardware acceleration
    secured_tps = np.array([810, 760, 610, 460, 260, 130, 65])
    
    df = pd.DataFrame({
        'Payload Size (KB)': np.concatenate([payload_sizes_kb, payload_sizes_kb]),
        'Throughput (Req/Sec)': np.concatenate([baseline_tps, secured_tps]),
        'Protocol': ['Baseline (Plaintext)'] * len(payload_sizes_kb) + ['Secured (AES-128 VPN)'] * len(payload_sizes_kb)
    })
    
    plt.figure(figsize=(10, 6))
    
    ax = sns.lineplot(
        data=df,
        x='Payload Size (KB)',
        y='Throughput (Req/Sec)',
        hue='Protocol',
        marker='o',
        markersize=9,
        linewidth=3,
        palette=[COLORS[2], COLORS[0]] # Light blue for baseline, Dark purple for secured
    )
    
    plt.title('Throughput Decay vs. Payload Size', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Telemetry Payload Size (KB)', fontsize=12, fontweight='bold')
    plt.ylabel('Throughput (Requests / Second)', fontsize=12, fontweight='bold')
    
    plt.xscale('log') # Log scale to handle 1KB to 1000KB cleanly
    plt.xticks(payload_sizes_kb, labels=[f"{x}KB" for x in payload_sizes_kb])
    
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(title='', fontsize=11)
    sns.despine(left=True, bottom=True)
    
    plt.tight_layout()
    
    out_file = os.path.join(OUTPUT_DIR, 'throughput_decay.png')
    plt.savefig(out_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    shutil.copy(out_file, os.path.join(ARTIFACT_DIR, 'throughput_decay.png'))
    print(f"Saved {out_file}")

if __name__ == "__main__":
    generate_security_time_budget()
    generate_throughput_decay()
    print("Advanced visualizations generated successfully.")
