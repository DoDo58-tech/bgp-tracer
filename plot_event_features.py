#!/usr/bin/env python3
"""
BGP事件特征可视化工具
为每个事件生成多个特征对比图，纵向排列，异常时间段用荧光色标注
"""
import json
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Rectangle
from datetime import datetime
from pathlib import Path
import numpy as np
from typing import Dict, List
import pandas as pd

# 字体设置（使用 DejaVu，避免中文字体在不同环境下缺失导致图例乱码）
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 输入输出路径
DATA_DIR = Path(__file__).parent / "data"
INPUT_FILE = DATA_DIR / "event_features" / "event_features_analysis.json"  # 仍用于读取事件元数据
CSV_DIR = DATA_DIR / "event_features" / "timeseries_csv"  # CSV文件目录
OUTPUT_DIR = DATA_DIR / "event_plots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# 要可视化的核心特征（精选10个最关键的）
FEATURES_TO_PLOT = [
    # 1. 基础流量特征（3个）
    ('announcement_count', '① BGP公告数量', '次数'),
    ('withdrawal_count', '② BGP撤销数量', '次数'),
    ('flapping_prefix_count', '③ 路由震荡前缀数 ⭐', '个'),
    
    # 2. 路由劫持/泄露核心特征（3个）⭐⭐⭐
    ('ori_change_rate', '④ 起源AS变化比例 ⭐⭐⭐', '比例'),
    ('num_ori_change', '⑤ 起源AS变化次数 ⭐⭐⭐', '次数'),
    ('path_change_rate', '⑥ 路径长度变化比例 ⭐⭐', '比例'),
    
    # 3. BGP风暴/异常行为特征（2个）
    ('dup_A_rate', '⑦ 重复公告比例 ⭐', '比例'),
    ('avg_arrival_interval', '⑧ 平均消息到达间隔 ⭐', '秒'),
    
    # 4. 路径多样性特征（2个）
    ('editDis_entropy', '⑨ AS路径变化熵 ⭐', '熵值'),
    ('unique_as_count', '⑩ 涉及AS数量', '个'),
]


def load_event_data(json_file: Path) -> List[Dict]:
    """加载事件数据"""
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data


def load_timeseries_from_csv(event_name: str) -> pd.DataFrame:
    """从CSV文件加载时间序列数据"""
    csv_file = CSV_DIR / f"{event_name}_timeseries.csv"
    
    if not csv_file.exists():
        print(f"  警告: CSV文件不存在: {csv_file}")
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(csv_file, encoding='utf-8')
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        return df
    except Exception as e:
        print(f"  警告: 读取CSV文件失败: {csv_file}, 错误: {e}")
        return pd.DataFrame()


def prepare_timeseries_data(event_data: Dict) -> pd.DataFrame:
    """将时序数据转换为DataFrame（备用方法，优先使用CSV）"""
    # 优先从CSV读取
    event_name = event_data.get('event_name', '')
    csv_file = CSV_DIR / f"{event_name}_timeseries.csv"
    
    if csv_file.exists():
        return load_timeseries_from_csv(event_name)
    
    # 如果CSV不存在，从JSON中的timeseries_plot读取（向后兼容）
    plot_timeseries = event_data.get('timeseries_plot', {})
    if not plot_timeseries:
        # 尝试从timeseries_event合并
        event_ts = event_data.get('timeseries_event', {})
        baseline_ts = event_data.get('timeseries_baseline', {})
        plot_timeseries = {**baseline_ts, **event_ts}
    
    if not plot_timeseries:
        return pd.DataFrame()
    
    # 转换为列表
    data_list = []
    for timestamp_str, features in plot_timeseries.items():
        row = {'timestamp': datetime.fromisoformat(timestamp_str)}
        row.update(features)
        data_list.append(row)
    
    df = pd.DataFrame(data_list)
    df = df.sort_values('timestamp')
    return df


def plot_event_features(event_data: Dict, output_dir: Path):
    """为单个事件绘制特征对比图（折线图，时间范围：start_time-1天 ~ end_time+1天）"""
    from datetime import timedelta
    
    event_name = event_data['event_name']
    print(f"绘制事件: {event_name}")
    
    # 获取异常时间段
    anomaly_start = datetime.fromisoformat(event_data['start_time'])
    anomaly_end = datetime.fromisoformat(event_data['end_time'])
    
    # 计算时间范围：start_time-1天 ~ end_time+1天
    plot_start = anomaly_start - timedelta(days=1)
    plot_end = anomaly_end + timedelta(days=1)
    
    # 从CSV文件读取时间序列数据
    df = load_timeseries_from_csv(event_name)
    
    if df.empty:
        # 如果CSV不存在，尝试从JSON读取（向后兼容）
        print(f"  警告: CSV文件不存在，尝试从JSON读取")
        df = prepare_timeseries_data(event_data)
    
    if df.empty:
        print(f"  警告: {event_name} 没有时序数据")
        return
    
    # 筛选时间范围内的数据
    df = df[(df['timestamp'] >= plot_start) & (df['timestamp'] <= plot_end)]
    
    if df.empty:
        print(f"  警告: {event_name} 在指定时间范围内没有数据")
        return
    
    # 计算需要绘制的特征数量
    available_features = [(feat, name, unit) for feat, name, unit in FEATURES_TO_PLOT 
                          if feat in df.columns]
    
    if not available_features:
        print(f"  警告: {event_name} 没有可绘制的特征")
        return
    
    n_features = len(available_features)
    
    # 创建图形：纵向排列，每个子图3英寸高（开启受限布局，避免标签被裁切）
    fig, axes = plt.subplots(n_features, 1, figsize=(16, 3 * n_features), constrained_layout=False)
    if n_features == 1:
        axes = [axes]
    
    fig.suptitle(f'BGP异常事件特征分析：{event_name}\n时间范围：{plot_start.strftime("%Y-%m-%d %H:%M")} ~ {plot_end.strftime("%Y-%m-%d %H:%M")} | 异常时段：{anomaly_start.strftime("%Y-%m-%d %H:%M")} ~ {anomaly_end.strftime("%Y-%m-%d %H:%M")}',
                 fontsize=14, fontweight='bold', y=0.995)
    
    # 为每个特征绘图
    for idx, (feature_name, display_name, unit) in enumerate(available_features):
        ax = axes[idx]
        
        # 提取所有数据点
        timestamps = df['timestamp'].values
        values = df[feature_name].values
        
        # 分离三个时间段的数据点
        before_mask = df['timestamp'] < anomaly_start  # 异常前（绿色）
        event_mask = (df['timestamp'] >= anomaly_start) & (df['timestamp'] <= anomaly_end)  # 异常时段
        after_mask = df['timestamp'] > anomaly_end  # 异常后（蓝色）
        
        # 先确定Y轴范围
        y_min = values.min()
        y_max = values.max()
        y_range = y_max - y_min
        if y_range == 0:
            y_range = 1
        # 添加10%的边距
        y_min -= y_range * 0.1
        y_max += y_range * 0.1
        
        # 先添加异常时间段背景（红色高亮区域）- 必须先添加背景
        anomaly_patch = Rectangle(
            (mdates.date2num(anomaly_start), y_min),
            mdates.date2num(anomaly_end) - mdates.date2num(anomaly_start),
            y_max - y_min,
            facecolor='red',  # 红色背景（如图）
            alpha=0.2,
            zorder=0
        )
        ax.add_patch(anomaly_patch)
        ax.set_ylim(y_min, y_max)
        
        # 绘制完整的折线图（每个时间点一个点，连成一条线）
        # 异常前数据（绿色）
        if before_mask.any():
            before_ts = df.loc[before_mask, 'timestamp'].values
            before_vals = df.loc[before_mask, feature_name].values
            ax.plot(before_ts, before_vals, color='green', linewidth=1.5, 
                   marker='o', markersize=3, alpha=0.8, zorder=3, label='before')
        
        # 异常时段和之后的数据（蓝色）- 根据图片描述
        event_and_after_mask = df['timestamp'] >= anomaly_start
        if event_and_after_mask.any():
            event_after_ts = df.loc[event_and_after_mask, 'timestamp'].values
            event_after_vals = df.loc[event_and_after_mask, feature_name].values
            ax.plot(event_after_ts, event_after_vals, color='blue', linewidth=1.5, 
                   marker='o', markersize=3, alpha=0.8, zorder=3, label='event+after')
        
        # 设置标题和标签（用特征名而非中文名）
        ax.set_title(f'{feature_name}', fontsize=12, fontweight='bold', pad=10)
        ax.set_ylabel('value', fontsize=10)
        ax.set_xlim(plot_start, plot_end)
        ax.grid(True, alpha=0.3, linestyle='--')
        # 只展示曲线的图例，避免空框；将图例放在轴内，减少裁切风险
        handles, labels = ax.get_legend_handles_labels()
        if handles:
            ax.legend(loc='upper right', fontsize=8, frameon=True)
        
        # 格式化x轴时间
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        ax.xaxis.set_major_locator(mdates.AutoDateLocator(maxticks=10))
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    # 调整布局：给y轴标签和图例预留边距
    plt.tight_layout(rect=[0.06, 0.04, 0.98, 0.98])
    
    # 保存图片
    output_file = output_dir / f"{event_name}_features.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"  保存到: {output_file}")
    plt.close()


def plot_feature_heatmap(event_data: Dict, output_dir: Path):
    """为单个事件绘制特征热力图（异常程度）"""
    event_name = event_data['event_name']
    anomalies = event_data.get('anomalies', [])
    
    if not anomalies:
        print(f"  {event_name}: 无异常特征，跳过热力图")
        return
    
    # 按时间戳和特征组织数据
    anomaly_dict = {}
    for anomaly in anomalies:
        ts = anomaly['timestamp']
        feat = anomaly['feature']
        z_score = abs(anomaly.get('z_score', 0))
        
        if ts not in anomaly_dict:
            anomaly_dict[ts] = {}
        anomaly_dict[ts][feat] = z_score
    
    # 转换为DataFrame
    df = pd.DataFrame(anomaly_dict).T
    df.index = pd.to_datetime(df.index)
    df = df.sort_index()
    
    if df.empty:
        return
    
    # 创建热力图
    fig, ax = plt.subplots(figsize=(14, max(8, len(df.columns) * 0.5)))
    
    im = ax.imshow(df.T.values, aspect='auto', cmap='YlOrRd', 
                   interpolation='nearest')
    
    # 设置标签
    ax.set_xticks(np.arange(len(df.index)))
    ax.set_yticks(np.arange(len(df.columns)))
    ax.set_xticklabels([t.strftime('%m-%d %H:%M') for t in df.index], rotation=45, ha='right')
    ax.set_yticklabels(df.columns)
    
    # 添加颜色条
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('异常程度 (|Z-Score|)', rotation=270, labelpad=20)
    
    # 在格子中显示数值
    for i in range(len(df.columns)):
        for j in range(len(df.index)):
            text = ax.text(j, i, f'{df.T.values[i, j]:.1f}',
                          ha="center", va="center", color="black", fontsize=8)
    
    ax.set_title(f'特征异常热力图：{event_name}', fontsize=14, fontweight='bold', pad=20)
    ax.set_xlabel('时间', fontsize=12)
    ax.set_ylabel('特征名称', fontsize=12)
    
    plt.tight_layout()
    
    # 保存
    output_file = output_dir / f"{event_name}_heatmap.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"  热力图保存到: {output_file}")
    plt.close()


def generate_summary_report(events_data: List[Dict], output_dir: Path):
    """生成汇总报告"""
    report_file = output_dir / "visualization_summary.txt"
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("BGP事件特征可视化汇总报告\n")
        f.write("=" * 80 + "\n\n")
        
        for event in events_data:
            event_name = event['event_name']
            anomaly_count = len(event.get('anomalies', []))
            timeseries_size = len(event.get('timeseries_event', {}))
            
            f.write(f"事件: {event_name}\n")
            f.write(f"  异常时间段: {event['start_time']} ~ {event['end_time']}\n")
            f.write(f"  时序数据点: {timeseries_size}\n")
            f.write(f"  检测到的异常: {anomaly_count} 个\n")
            f.write(f"  图片文件:\n")
            f.write(f"    - {event_name}_features.png (特征时序图)\n")
            if anomaly_count > 0:
                f.write(f"    - {event_name}_heatmap.png (异常热力图)\n")
            f.write("\n")
    
    print(f"\n汇总报告保存到: {report_file}")


def main():
    print("=" * 80)
    print("BGP事件特征可视化工具")
    print("=" * 80)
    print()
    
    # 检查输入文件
    if not INPUT_FILE.exists():
        print(f"错误: 找不到输入文件: {INPUT_FILE}")
        print("请先运行 extract_event_features.py 生成特征数据")
        return
    
    # 加载数据
    print(f"加载数据: {INPUT_FILE}")
    events_data = load_event_data(INPUT_FILE)
    print(f"找到 {len(events_data)} 个事件\n")
    
    # 为每个事件生成图表
    for idx, event_data in enumerate(events_data, 1):
        print(f"[{idx}/{len(events_data)}] ", end="")
        
        try:
            # 绘制特征时序图
            plot_event_features(event_data, OUTPUT_DIR)
            
            # 绘制异常热力图
            plot_feature_heatmap(event_data, OUTPUT_DIR)
            
        except Exception as e:
            print(f"  错误: {e}")
            import traceback
            traceback.print_exc()
    
    # 生成汇总报告
    generate_summary_report(events_data, OUTPUT_DIR)
    
    print("\n" + "=" * 80)
    print(f"所有图表已保存到: {OUTPUT_DIR}")
    print("=" * 80)


if __name__ == "__main__":
    main()

