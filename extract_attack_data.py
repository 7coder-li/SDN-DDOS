import pandas as pd
import numpy as np
import glob
import os

# ================= 配置路径 =================
TRAIN_ATTACK_PATH = '../train_set'
OUTPUT_PARQUET = 'Attack_2019_ALL_FEATURES.parquet'
TARGET_SAMPLES = 458831

def extract_balanced_attack_data():
    all_files = glob.glob(os.path.join(TRAIN_ATTACK_PATH, "*.csv"))
    num_files = len(all_files)
    
    if num_files == 0:
        print("错误：在 train_set 文件夹中没有找到 CSV 文件！")
        return

    # 为了保证最终能凑够 TARGET_SAMPLES，每个文件多提取 10% 作为冗余
    samples_per_file = int((TARGET_SAMPLES / num_files) * 1.1)
    print(f"共有 {num_files} 个攻击文件。")
    print(f"目标总数: {TARGET_SAMPLES} 条。")
    print(f"计划从每个文件中最多提取 {samples_per_file} 条样本以保证绝对均衡。\n")
    
    attack_list = []
    
    for file in all_files:
        filename = os.path.basename(file)
        print(f"[{filename}] 正在扫描...")
        file_attack_list = []
        try:
            # 使用 chunksize 避免内存溢出
            chunk_iter = pd.read_csv(file, chunksize=200000, low_memory=False)
            for chunk in chunk_iter:
                # 清理列名空格
                chunk.columns = chunk.columns.str.strip()
                if 'Label' not in chunk.columns:
                    continue
                
                # 过滤出非 BENIGN 的流量（即攻击流量）
                is_benign = chunk['Label'].astype(str).str.strip().str.upper() == 'BENIGN'
                a_chunk = chunk[~is_benign]
                
                if not a_chunk.empty:
                    file_attack_list.append(a_chunk)
                    
                # 如果当前文件提取的数量已经达到了 samples_per_file，就立刻停止读取当前文件
                if sum([len(df) for df in file_attack_list]) >= samples_per_file:
                    break
                    
            if file_attack_list:
                file_df = pd.concat(file_attack_list, ignore_index=True)
                # 如果当前文件提取的多了，就随机下采样到 samples_per_file
                if len(file_df) > samples_per_file:
                    file_df = file_df.sample(n=samples_per_file, random_state=42)
                
                attack_list.append(file_df)
                print(f"  -> 成功提取 {len(file_df)} 条攻击流量。")
            else:
                print(f"  -> [警告] 该文件中没有找到攻击流量。")
                
        except Exception as e:
            print(f"  -> [!] 读取失败: {e}")

    # 合并所有文件提取的数据
    print("\n正在合并所有提取的数据...")
    final_attack_df = pd.concat(attack_list, ignore_index=True)
    print(f"合并后共有 {len(final_attack_df)} 条混合攻击流量。")
    
    # 最终的精确下采样，确保总数严格等于 TARGET_SAMPLES
    if len(final_attack_df) > TARGET_SAMPLES:
        print(f"正在进行最终的全局随机下采样至精确的 {TARGET_SAMPLES} 条...")
        final_attack_df = final_attack_df.sample(n=TARGET_SAMPLES, random_state=42)
    elif len(final_attack_df) < TARGET_SAMPLES:
        print(f"[警告] 提取的总数 ({len(final_attack_df)}) 少于目标数量 ({TARGET_SAMPLES})！")
        
    # 修复 Parquet 序列化错误：将所有 object 类型的列强制转换为字符串
    print("正在清理混合数据类型以适配 Parquet 格式...")
    for col in final_attack_df.select_dtypes(include=['object', 'string']).columns:
        final_attack_df[col] = final_attack_df[col].astype(str)
        
    print(f"\n正在保存至全局缓存文件: {OUTPUT_PARQUET} ...")
    final_attack_df.to_parquet(OUTPUT_PARQUET, index=False)
    print("🎉 保存成功！以后训练模型可以直接读取这个 Parquet 文件了。")

if __name__ == "__main__":
    extract_balanced_attack_data()
