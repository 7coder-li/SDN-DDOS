import sys
import numpy as np
import numpy.core
import numpy.core.multiarray
import numpy.core.numeric
sys.modules['numpy._core'] = numpy.core
sys.modules['numpy._core.multiarray'] = numpy.core.multiarray
sys.modules['numpy._core.numeric'] = numpy.core.numeric

from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)

# 1. 加载训练好的模型和标准化器
print("Loading AI model and Scaler...")
try:
    model = joblib.load('ddos_final_model.pkl')
    scaler = joblib.load('final_scaler.pkl')
    print("[SUCCESS] Model loaded successfully! AI Engine is ready.")
except Exception as e:
    print(f"[ERROR] Model load failed: {e}")
    print("Please ensure ddos_final_model.pkl and final_scaler.pkl are in the current directory.")
    exit(1)

# 2. 定义特征顺序 (必须与训练时完全一致)
FEATURES = [
    'Protocol',
    'Flow Duration', 
    'Total Fwd Packets', 
    'Total Length of Fwd Packets',
    'Total Backward Packets',
    'Total Length of Bwd Packets',
    'Average Packet Size'
]

import subprocess

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # 获取 Ryu 发来的 JSON 数据
        data = request.json
        
        # 如果没有包，直接返回正常流量，无需经过模型计算
        if data.get('Total Fwd Packets', 0) == 0:
            return jsonify({
                'is_attack': False,
                'attack_probability': 0.0,
                'message': 'Normal Traffic (Idle)'
            }), 200
        
        # 提取特征并转换为 DataFrame (保持列名和顺序一致)
        feature_values = []
        for feat in FEATURES:
            if feat not in data:
                return jsonify({'error': f'Missing feature: {feat}'}), 400
            feature_values.append(data[feat])
            
        df_features = pd.DataFrame([feature_values], columns=FEATURES)
        
        # 数据标准化
        scaled_features = scaler.transform(df_features)
        
        # 模型预测
        prediction = model.predict(scaled_features)[0]
        probability = model.predict_proba(scaled_features)[0][1] # 攻击的概率
        
        # 恢复默认阈值 0.5，因为我们已经修复了 Flow Duration 的单位问题（微秒）
        is_attack = bool(probability > 0.5)
        
        print(f"[PREDICT] PPS: {data.get('Total Fwd Packets', 0):.1f}, AvgSize: {data.get('Average Packet Size', 0):.1f}, Duration: {data.get('Flow Duration', 0)} -> Prob: {probability:.2%}, IsAttack: {is_attack}")
        
        if is_attack:
            print(f"[ALERT] DDoS Attack Detected! Probability: {probability:.2%}")
        
        # 构造返回结果
        result = {
            'is_attack': is_attack,
            'attack_probability': float(probability),
            'message': 'DDoS Attack Detected!' if prediction == 1 else 'Normal Traffic'
        }
        
        return jsonify(result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/command', methods=['POST'])
def command():
    try:
        data = request.json
        host = data.get('host')
        cmd = data.get('command')
        if not host or not cmd:
            return jsonify({'error': 'Missing host or command'}), 400
            
        print(f"[MININET] Executing on {host}: {cmd}")
        
        # Robust command execution for Mininet hosts
        # 1. Try using the 'm' utility with sudo
        # 2. Fallback to finding the bash PID and using 'sudo mnexec'
        script = f"""
        echo "[$(date)] Executing on {host}: {cmd}" >> /tmp/mininet_api.log
        
        # Try docker exec first if mininet is in a container
        if docker ps | grep -q mininet; then
            echo "Trying docker exec..." >> /tmp/mininet_api.log
            docker exec mininet bash -c "m {host} {cmd}" >> /tmp/mininet_api.log 2>&1
            if [ $? -eq 0 ]; then exit 0; fi
        fi

        # Try m utility
        if command -v m >/dev/null 2>&1; then
            sudo m {host} {cmd} >> /tmp/mininet_api.log 2>&1
            if [ $? -ne 0 ]; then
                echo "[ERROR] 'sudo m' failed." >> /tmp/mininet_api.log
            fi
        else
            # Find the PID of the mininet host process
            # Mininet hosts usually run as 'bash' with an environment variable or specific arguments
            # Let's try a few different ways to find it
            PID=$(ps ax | grep -E "mininet:.*{host}\\b" | grep -v grep | awk '{{print $1}}' | head -n 1)
            
            if [ -z "$PID" ]; then
                # Try finding bash processes that might be mininet hosts
                # This is a bit hacky but works in some environments
                PID=$(ps axww | grep "bash" | grep "\-m" | grep "mininet" | grep "{host}" | grep -v grep | awk '{{print $1}}' | head -n 1)
            fi
            
            if [ -n "$PID" ]; then
                echo "Found PID $PID for {host}, using mnexec..." >> /tmp/mininet_api.log
                sudo mnexec -a $PID {cmd} >> /tmp/mininet_api.log 2>&1
                if [ $? -ne 0 ]; then
                    echo "[ERROR] 'sudo mnexec' failed." >> /tmp/mininet_api.log
                fi
            else
                echo "[ERROR] Could not find PID for host {host}. Is the host name correct?" >> /tmp/mininet_api.log
                # As a last resort, if we are running on the same machine and have the mininet CLI open,
                # we can't easily inject commands without 'm' or 'mnexec' + PID.
                exit 1
            fi
        fi
        """
        
        # Run command in background
        subprocess.Popen(script, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return jsonify({'success': True, 'output': f'Command started on {host}'}), 200
    except Exception as e:
        print(f"[ERROR] Command failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    try:
        import os
        if os.path.exists('/tmp/mininet_api.log'):
            with open('/tmp/mininet_api.log', 'r') as f:
                logs = f.read()
            return jsonify({'logs': logs}), 200
        else:
            return jsonify({'logs': 'No logs found.'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # 启动 API 服务，监听 5000 端口
    app.run(host='0.0.0.0', port=5000, debug=False)
