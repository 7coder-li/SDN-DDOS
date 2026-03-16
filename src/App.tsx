import React, { useState, useEffect, useCallback } from 'react';
import { Flow, TrafficStats, DetectionResult, TopologyData } from './types';
import { detectDDoS } from './services/mlEngine';
import { Topology } from './components/Topology';
import { TrafficChart } from './components/TrafficChart';
import { FlowTable } from './components/FlowTable';
import { DetectionStatus } from './components/DetectionStatus';
import { SystemLogs } from './components/SystemLogs';
import { Activity, Shield, Database, Network, Cpu, Terminal } from 'lucide-react';
import { motion } from 'motion/react';

export default function App() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [topology, setTopology] = useState<TopologyData>({ switches: [], links: [], hosts: [] });
  const [stats, setStats] = useState<TrafficStats[]>([]);
  const [detection, setDetection] = useState<DetectionResult>({ isAttack: false, confidence: 0 });
  const [metrics, setMetrics] = useState({ throughput: 0, attackCount: 0 });
  const [activeAttacks, setActiveAttacks] = useState<string[]>([]);
  const [logs, setLogs] = useState<any[]>([]);

  const fetchStats = useCallback(async () => {
    try {
      const [statsRes, logsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/logs')
      ]);
      
      if (!statsRes.ok) throw new Error('Network response was not ok');
      
      const data = await statsRes.json();
      const logsData = await logsRes.json();
      
      setFlows(data.flows || []);
      setTopology(data.topology || { switches: [], links: [], hosts: [] });
      setMetrics(data.metrics || { throughput: 0, attackCount: 0 });
      setActiveAttacks(data.activeAttacks || []);
      setLogs(logsData || []);

      // 更新统计图表
      const totalPPS = (data.flows || [])
        .filter((f: Flow) => f.status === 'active')
        .reduce((acc: number, f: Flow) => acc + f.pps, 0);
      const newStat: TrafficStats = {
        timestamp: Date.now(),
        packetRate: totalPPS, 
        byteRate: data.metrics?.throughput || 0,
        activeFlows: (data.flows || []).filter((f: Flow) => f.status === 'active').length
      };

      setStats(prev => [...prev.slice(-29), newStat]);

      // 机器学习检测
      if (data.flows?.length > 0) {
        detectDDoS(data.flows)
          .then(result => setDetection(result))
          .catch(() => {});
      } else {
        setDetection({ isAttack: false, confidence: 0.99, reason: "等待流量输入..." });
      }

    } catch (error) {
      console.error('无法获取统计数据:', error);
    }
  }, []);

  useEffect(() => {
    let timeoutId: NodeJS.Timeout;
    const loop = async () => {
      await fetchStats();
      timeoutId = setTimeout(loop, 1000);
    };
    loop();
    return () => clearTimeout(timeoutId);
  }, [fetchStats]);

  const handleBlock = async (src: string, dst: string, block: boolean) => {
    try {
      await fetch('/api/control/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ src, dst, block })
      });
      fetchStats();
    } catch (error) {
      console.error('拦截指令下发失败:', error);
    }
  };

  const triggerAttack = async (type: string, active: boolean) => {
    try {
      await fetch('/api/control/attack', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, active })
      });
      fetchStats();
    } catch (error) {
      console.error('攻击模拟失败:', error);
    }
  };

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
      {/* Header */}
      <header className="border-b border-[#141414] p-6 flex justify-between items-end">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Shield size={20} />
            <span className="text-[10px] font-mono uppercase tracking-[0.2em] font-bold">SDN 安全框架 v1.0</span>
          </div>
          <h1 className="text-5xl font-serif italic tracking-tighter leading-none">
            DDoS 攻击检测与缓解系统
          </h1>
        </div>
        <div className="text-right hidden md:block">
          <p className="text-[10px] font-mono uppercase opacity-50">系统状态</p>
          <p className="text-xs font-bold flex items-center gap-2 justify-end">
            <Activity size={14} className="text-emerald-600" /> 实时联动中
          </p>
        </div>
      </header>

      {/* Main Grid */}
      <main className="grid grid-cols-1 lg:grid-cols-12 gap-0 border-b border-[#141414]">
        {/* Left Column: Stats & Detection */}
        <div className="lg:col-span-4 border-r border-[#141414] flex flex-col">
          <div className="p-6 border-b border-[#141414]">
            <DetectionStatus 
              result={detection} 
              activeAttacks={activeAttacks}
              onSimulate={triggerAttack} 
            />
          </div>
          <div className="p-6 flex-grow">
            <h3 className="text-[11px] font-serif italic uppercase tracking-wider mb-4 opacity-50">系统指标</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="border border-[#141414] p-4">
                <Database size={16} className="mb-2 opacity-50" />
                <p className="text-[10px] font-mono uppercase opacity-50">活跃流表项</p>
                <p className="text-2xl font-mono">{flows.filter(f => f.status === 'active' || f.status === 'blocked').length}</p>
              </div>
              <div className="border border-[#141414] p-4">
                <Network size={16} className="mb-2 opacity-50" />
                <p className="text-[10px] font-mono uppercase opacity-50">拦截流量数</p>
                <p className="text-2xl font-mono">{flows.filter(f => f.status === 'blocked').length}</p>
              </div>
              <div className="border border-[#141414] p-4">
                <Activity size={16} className="mb-2 opacity-50" />
                <p className="text-[10px] font-mono uppercase opacity-50">当前吞吐量</p>
                <p className="text-2xl font-mono">{(metrics.throughput / 1000000).toFixed(2)} Mbps</p>
              </div>
              <div className="border border-[#141414] p-4">
                <Shield size={16} className="mb-2 opacity-50" />
                <p className="text-[10px] font-mono uppercase opacity-50">恶意流量数</p>
                <p className="text-2xl font-mono text-red-600">{metrics.attackCount}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Center Column: Visualization */}
        <div className="lg:col-span-8 flex flex-col">
          <div className="grid grid-cols-1 md:grid-cols-2 border-b border-[#141414]">
            <div className="p-6 border-r border-[#141414]">
              <h3 className="text-[11px] font-serif italic uppercase tracking-wider mb-4 opacity-50">网络拓扑 (Mininet 实时结构)</h3>
              <div className="aspect-video">
                <Topology />
              </div>
            </div>
            <div className="flex flex-col border-b md:border-b-0">
              <div className="p-6 border-b border-[#141414] flex-grow">
                <TrafficChart data={stats} />
              </div>
              <div className="p-6 h-48">
                <SystemLogs logs={logs} />
              </div>
            </div>
          </div>
          
          <div className="p-6 flex-grow bg-[#141414]/5">
            <div className="flex justify-between items-end mb-4">
              <h3 className="text-[11px] font-serif italic uppercase tracking-wider opacity-50">SDN 控制器流表 (Ryu 实时数据)</h3>
              <span className="text-[9px] font-mono uppercase bg-[#141414] text-[#E4E3E0] px-2 py-0.5">北向接口: REST API</span>
            </div>
            <FlowTable flows={flows} onBlock={handleBlock} />
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="p-6 flex flex-col md:flex-row justify-between items-center gap-4 text-[10px] font-mono uppercase opacity-50">
        <div className="flex gap-6">
          <span>OpenFlow v1.3</span>
          <span>控制器: Ryu</span>
          <span>仿真环境: Mininet</span>
        </div>
        <div>
        </div>
      </footer>
    </div>
  );
}
