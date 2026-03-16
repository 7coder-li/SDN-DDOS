import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# ================= 配置路径 =================
BENIGN_PARQUET_PATH = '../Benign-Monday-no-metadata.parquet' 
ATTACK_CACHE_PATH = 'Attack_2019_ALL_FEATURES.parquet' # 直接使用提取好的全局缓存

# ================= 特征选择 =================
# 7特征终极版：加入了 Protocol (协议)，这是区分正常业务(TCP为主)和反射型DDoS(UDP为主)的杀手锏！
FEATURES = [
    'Protocol',
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Length of Fwd Packets',
    'Total Backward Packets',
    'Total Length of Bwd Packets',
    'Average Packet Size'
]

def standardize_columns(df):
    """统一 2017 和 2019 数据集的列名"""
    df.columns = df.columns.str.strip()
    rename_map = {
        'Fwd Packets Length Total': 'Total Length of Fwd Packets',
        'Packet Length Mean': 'Average Packet Size',
        'Fwd Packet Length Mean': 'Average Packet Size',
        'Bwd Packets Total': 'Total Backward Packets',
        'Bwd Packets Length Total': 'Total Length of Bwd Packets'
    }
    for old_name, new_name in rename_map.items():
        if old_name in df.columns and new_name not in df.columns:
            df.rename(columns={old_name: new_name}, inplace=True)
    return df

# ================= 主流程 =================

# 1. 加载正常流量
print(f"\n[1/3] 正在加载 CIC-IDS-2017 正常流量...")
benign_df = pd.read_parquet(BENIGN_PARQUET_PATH)
benign_df = standardize_columns(benign_df)
benign_df['Label'] = 0
print(f"  => 成功加载 {len(benign_df)} 条正常流量！")

# 2. 加载攻击流量 (直接读取缓存)
print(f"\n[2/3] 正在加载 CIC-DDoS2019 攻击流量 (从缓存 {ATTACK_CACHE_PATH})...")
try:
    attack_df = pd.read_parquet(ATTACK_CACHE_PATH)
    attack_df = standardize_columns(attack_df)
    attack_df['Label'] = 1
    print(f"  => 成功加载 {len(attack_df)} 条攻击流量！")
except FileNotFoundError:
    print(f"\n[!] 错误：找不到 {ATTACK_CACHE_PATH}！")
    print("请先运行 `python extract_attack_data.py` 提取攻击流量。")
    exit(1)

# 3. 特征过滤与合并
print("\n正在过滤特征并合并数据集...")
# 确保特征存在，缺失补0
for feat in FEATURES:
    if feat not in benign_df.columns: benign_df[feat] = 0
    if feat not in attack_df.columns: attack_df[feat] = 0

benign_df = benign_df[FEATURES + ['Label']].replace([np.inf, -np.inf], np.nan).dropna()
attack_df = attack_df[FEATURES + ['Label']].replace([np.inf, -np.inf], np.nan).dropna()

# 划分训练集和测试集
b_train, b_test = train_test_split(benign_df, test_size=0.2, random_state=42)
a_train, a_test = train_test_split(attack_df, test_size=0.2, random_state=42)

train_df = pd.concat([b_train, a_train], ignore_index=True).sample(frac=1, random_state=42)
test_df = pd.concat([b_test, a_test], ignore_index=True).sample(frac=1, random_state=42)

X_train = train_df[FEATURES]
y_train = train_df['Label']
X_test = test_df[FEATURES]
y_test = test_df['Label']

# 4. 标准化
print("正在进行数据标准化...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 5. 训练模型
print(f"\n[3/3] 正在使用 {len(train_df)} 条数据训练终极版随机森林模型...")
model = RandomForestClassifier(n_estimators=200, class_weight='balanced', n_jobs=-1, random_state=42)
model.fit(X_train_scaled, y_train)

# 6. 评估模型
print("\n正在评估模型...")
y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

print("\n" + "="*55)
print(f"   百万级融合版：跨数据集验证报告 (7特征终极版)")
print("="*55)
print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack'], digits=4))

# ================= 论文图表生成 =================
print("\n📊 正在生成论文级专业图表...")
sns.set_theme(style="whitegrid")
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

plt.figure(figsize=(8, 6))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'], annot_kws={"size": 16})
plt.title('Confusion Matrix (7 Features)', fontsize=16)
plt.ylabel('True Label', fontsize=14)
plt.xlabel('Predicted Label', fontsize=14)
plt.tight_layout()
plt.savefig('thesis_confusion_matrix.png', dpi=300)
plt.close()

plt.figure(figsize=(8, 6))
fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
roc_auc = auc(fpr, tpr)
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate', fontsize=14)
plt.ylabel('True Positive Rate', fontsize=14)
plt.title('Receiver Operating Characteristic (ROC)', fontsize=16)
plt.legend(loc="lower right", fontsize=12)
plt.tight_layout()
plt.savefig('thesis_roc_curve.png', dpi=300)
plt.close()

plt.figure(figsize=(10, 6))
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
sorted_features = [FEATURES[i] for i in indices]
sns.barplot(x=importances[indices], y=sorted_features, palette="viridis")
plt.title('Feature Importance in Random Forest', fontsize=16)
plt.xlabel('Relative Importance', fontsize=14)
plt.tight_layout()
plt.savefig('thesis_feature_importance.png', dpi=300)
plt.close()

joblib.dump(model, 'ddos_final_model.pkl')
joblib.dump(scaler, 'final_scaler.pkl')
print("\n🎉 模型已保存为 ddos_final_model.pkl！")
print("📸 论文图表已生成：thesis_confusion_matrix.png, thesis_roc_curve.png, thesis_feature_importance.png")
