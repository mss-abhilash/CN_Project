import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import shutil

# Set styling
# User palette: #473472, #53629E, #87BAC3, #D6F4ED
COLORS = ['#473472', '#53629E', '#87BAC3', '#D6F4ED']
sns.set_theme(style="whitegrid")
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Inter', 'Roboto', 'Arial']
plt.rcParams['axes.prop_cycle'] = plt.cycler(color=COLORS)

# Directories
DATA_DIR = 'scripts'
OUTPUT_DIR = 'research'
ARTIFACT_DIR = '/Users/maurya.pg13/.gemini/antigravity/brain/98a69d89-5866-4d14-a012-9e73c7724757/artifacts'

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_DIR, exist_ok=True)

def generate_comparative_plot():
    csv_path = os.path.join(DATA_DIR, 'comparative_results.csv')
    if not os.path.exists(csv_path):
        print(f"Skipping comparative plot: {csv_path} not found.")
        return
    
    df = pd.read_csv(csv_path)
    
    # Melt the dataframe for easier plotting with seaborn
    df_melted = df.melt(id_vars='protocol', value_vars=['avg_ms', 'p95_ms'], 
                        var_name='Metric', value_name='Latency (ms)')
    
    # Prettify labels
    df_melted['Metric'] = df_melted['Metric'].map({'avg_ms': 'Average Latency', 'p95_ms': '95th Percentile Latency'})
    df_melted['protocol'] = df_melted['protocol'].map({
        'plain': 'Plain Text (Insecure)',
        'tls_sim': 'TLS Overhead (Simulated)',
        'vpn_aes': 'Custom VPN (AES-128)'
    })
    
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(
        data=df_melted, 
        x='protocol', 
        y='Latency (ms)', 
        hue='Metric',
        palette=COLORS[:2],
        edgecolor='black',
        linewidth=0.5
    )
    
    plt.title('Performance Comparison: Custom VPN vs. TLS Overhead', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Protocol Configuration', fontsize=12, fontweight='bold')
    plt.ylabel('Latency (ms)', fontsize=12, fontweight='bold')
    
    # Annotate bars
    for p in ax.patches:
        ax.annotate(format(p.get_height(), '.2f'), 
                    (p.get_x() + p.get_width() / 2., p.get_height()), 
                    ha = 'center', va = 'center', 
                    xytext = (0, 9), 
                    textcoords = 'offset points',
                    fontsize=10)
    
    plt.legend(title='', fontsize=11)
    sns.despine(left=True, bottom=True)
    plt.tight_layout()
    
    out_file = os.path.join(OUTPUT_DIR, 'comparative_latency.png')
    plt.savefig(out_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    # Copy to artifact dir
    shutil.copy(out_file, os.path.join(ARTIFACT_DIR, 'comparative_latency.png'))
    print(f"Saved {out_file}")

def generate_scalability_plot():
    csv_path = os.path.join(DATA_DIR, 'scalability_results.csv')
    if not os.path.exists(csv_path):
        print(f"Skipping scalability plot: {csv_path} not found.")
        return
        
    df = pd.read_csv(csv_path)
    
    # Calculate means grouped by device_count
    df_grouped = df.groupby('device_count').mean().reset_index()
    
    # Plot Average Authentication vs Telemetry time
    df_melted = df_grouped.melt(id_vars='device_count', 
                                value_vars=['avg_auth_ms', 'avg_telem_ms'],
                                var_name='Operation', 
                                value_name='Average Time (ms)')
                                
    df_melted['Operation'] = df_melted['Operation'].map({
        'avg_auth_ms': 'Authentication Phase', 
        'avg_telem_ms': 'Telemetry Phase'
    })
    
    plt.figure(figsize=(10, 6))
    
    ax = sns.lineplot(
        data=df_melted,
        x='device_count',
        y='Average Time (ms)',
        hue='Operation',
        marker='o',
        markersize=10,
        linewidth=3,
        palette=[COLORS[0], COLORS[2]]
    )
    
    plt.title('Scalability Analysis: Concurrent Device Handling', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Number of Concurrent Devices', fontsize=12, fontweight='bold')
    plt.ylabel('Average Processing Time (ms)', fontsize=12, fontweight='bold')
    
    plt.xticks(df_grouped['device_count'].unique())
    plt.grid(True, linestyle='--', alpha=0.7)
    
    plt.legend(title='', fontsize=11)
    sns.despine(left=True, bottom=True)
    plt.tight_layout()
    
    out_file = os.path.join(OUTPUT_DIR, 'scalability_metrics.png')
    plt.savefig(out_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    # Copy to artifact dir
    shutil.copy(out_file, os.path.join(ARTIFACT_DIR, 'scalability_metrics.png'))
    print(f"Saved {out_file}")

if __name__ == "__main__":
    generate_comparative_plot()
    generate_scalability_plot()
    print("Visualizations generated successfully.")
