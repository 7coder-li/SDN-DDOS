import React from 'react';
import { Flow } from '../types';
import { Ban, CheckCircle, AlertCircle, ShieldAlert } from 'lucide-react';

interface Props {
  flows: Flow[];
  onBlock: (src: string, dst: string, block: boolean) => void;
}

export const FlowTable: React.FC<Props> = ({ flows, onBlock }) => {
  return (
    <div className="w-full border border-[#141414] bg-[#E4E3E0]">
      <div className="grid grid-cols-7 p-2 border-b border-[#141414] bg-[#141414] text-[#E4E3E0] text-[10px] font-mono uppercase tracking-tighter">
        <div>源 IP</div>
        <div>目的 IP</div>
        <div>流量类型</div>
        <div>置信度</div>
        <div>速率 (PPS)</div>
        <div>带宽 (Kbps)</div>
        <div>操作</div>
      </div>
      <div className="max-h-96 overflow-y-auto">
        {flows.length === 0 ? (
          <div className="p-8 text-center text-[11px] font-mono opacity-50 italic">
            等待流量输入... (请在 Mininet 中执行 ping 或 hping3)
          </div>
        ) : (
          flows
            .filter(flow => {
              const isBlocked = flow.status === 'blocked';
              const isActive = flow.status === 'active';
              const isMalicious = flow.isMalicious;
              
              // 过滤掉不活跃的正常流量（白色背景）
              if (!isMalicious && !isActive && !isBlocked) return false;
              
              // 过滤掉目的 IP 为 ANY 的混乱流量
              if (flow.dst === 'ANY' || flow.src.startsWith('Port-')) return false;
              
              return true;
            })
            .map((flow) => {
              const isBlocked = flow.status === 'blocked';
              const isActive = flow.status === 'active';
              const isMalicious = flow.isMalicious;

              // 背景颜色逻辑
              let bgColor = 'bg-white';
              if (isMalicious && isActive) bgColor = 'bg-red-500 text-white';
              else if (!isMalicious && isActive) bgColor = 'bg-emerald-500 text-white';
              else if (isMalicious && !isActive) bgColor = 'bg-gray-400 text-[#141414] opacity-80';
              else if (!isMalicious && !isActive) bgColor = 'bg-white text-[#141414]';

            return (
              <div 
                key={flow.id} 
                className={`grid grid-cols-7 p-2 border-b border-[#141414] text-[11px] font-mono transition-all group ${bgColor}`}
              >
                <div className="truncate flex items-center gap-1">
                  {isMalicious && isActive && <ShieldAlert size={10} className="animate-pulse" />}
                  {flow.src}
                </div>
                <div className="truncate">{flow.dst}</div>
                <div className="font-bold">{flow.type}</div>
                <div className="font-bold">{(flow.confidence * 100).toFixed(1)}%</div>
                <div className="font-bold">{flow.pps.toLocaleString()}</div>
                <div>{(flow.bps / 1000).toFixed(1)}</div>
                <div className="flex items-center gap-2">
                  {isBlocked ? (
                    <button 
                      onClick={() => onBlock(flow.src, flow.dst, false)}
                      className={`flex items-center gap-1 font-bold uppercase text-[9px] border px-1 transition-all ${
                        isMalicious ? 'border-white text-white hover:bg-white hover:text-red-500' : 'border-[#141414] text-[#141414] hover:bg-[#141414] hover:text-white'
                      }`}
                    >
                      <CheckCircle size={10} /> 解除
                    </button>
                  ) : (
                    <button 
                      onClick={() => onBlock(flow.src, flow.dst, true)}
                      className={`flex items-center gap-1 font-bold uppercase text-[9px] border px-1 transition-all ${
                        isActive ? 'border-white text-white hover:bg-white hover:text-red-500' : 'border-red-600 text-red-600 hover:bg-red-600 hover:text-white'
                      }`}
                    >
                      <Ban size={10} /> 拦截
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
