import React, { useState } from 'react';
import { DetectionResult } from '../types';
import { AlertTriangle, ShieldCheck, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

interface Props {
  result: DetectionResult;
  activeAttacks: string[];
  onSimulate: (type: string, active: boolean) => void;
}

export const DetectionStatus: React.FC<Props> = ({ result, activeAttacks, onSimulate }) => {
  const attackTypes = [
    { id: 'SYN_FLOOD', label: 'SYN Flood', icon: '🔥' },
    { id: 'UDP_FLOOD', label: 'UDP Flood', icon: '🌊' },
    { id: 'DNS_REFLECTION', label: 'DNS 反射', icon: '📡' },
    { id: 'HTTP_FLOOD', label: 'HTTP Flood', icon: '🌐' },
  ];

  const handleToggle = (id: string) => {
    const isActive = activeAttacks.includes(id);
    onSimulate(id, !isActive);
  };

  return (
    <div className="border border-[#141414] bg-[#E4E3E0] p-6 flex flex-col gap-4">
      <div className="flex justify-between items-start">
        <h2 className="text-2xl font-serif italic tracking-tight">检测引擎</h2>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono uppercase opacity-50">状态:</span>
          <div className={`w-2 h-2 rounded-full ${result.isAttack ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'}`} />
        </div>
      </div>

      <AnimatePresence mode="wait">
        {result.isAttack ? (
          <motion.div 
            key="attack"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="bg-red-500 text-[#E4E3E0] p-4 flex flex-col gap-2"
          >
            <div className="flex items-center gap-4">
              <AlertTriangle size={32} />
              <div>
                <p className="font-mono font-bold text-sm uppercase">
                  {result.attackers && result.attackers.length > 1 ? '检测到多重 DDoS 攻击' : '检测到 DDoS 攻击'}
                </p>
                <p className="text-[11px] opacity-90">{result.reason || "流量异常，疑似攻击"}</p>
                <p className="text-[11px] mt-1 font-bold">置信度: {(result.confidence * 100).toFixed(1)}%</p>
              </div>
            </div>
          </motion.div>
        ) : (
          <motion.div 
            key="normal"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="bg-[#141414] text-[#E4E3E0] p-4 flex items-center gap-4"
          >
            <ShieldCheck size={32} />
            <div>
              <p className="font-mono font-bold text-sm uppercase">网络安全</p>
              <p className="text-[11px] opacity-90">未发现恶意模式。</p>
              <p className="text-[11px] mt-1">置信度: {(result.confidence * 100).toFixed(1)}%</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid grid-cols-2 gap-4 mt-2">
        <div className="border border-[#141414] p-3">
          <p className="text-[9px] font-mono uppercase opacity-50 mb-1">机器学习模型</p>
          <p className="text-xs font-bold">随机森林 (Random Forest - CICDDoS2019 & CICIDS2017 训练)</p>
        </div>
        <div className="border border-[#141414] p-3">
          <p className="text-[9px] font-mono uppercase opacity-50 mb-1">特征工程 (7 维特征)</p>
          <p className="text-[10px] font-bold leading-tight">持续时间, 包数, 字节数, Pps, Bps, 平均包大小, 标志位</p>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <p className="text-[9px] font-mono uppercase opacity-50">模拟攻击控制 (开关):</p>
        <div className="grid grid-cols-2 gap-2">
          {attackTypes.map((type) => {
            const isActive = activeAttacks.includes(type.id);
            return (
              <button 
                key={type.id}
                onClick={() => handleToggle(type.id)}
                className={`border border-[#141414] py-2 px-1 font-mono text-[10px] uppercase transition-all flex items-center justify-center gap-2 ${
                  isActive 
                    ? 'bg-red-500 text-white animate-pulse' 
                    : 'bg-[#141414] text-[#E4E3E0] hover:bg-[#E4E3E0] hover:text-[#141414]'
                }`}
              >
                <span>{type.icon}</span>
                {isActive ? '停止' : '启动'} {type.label}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
