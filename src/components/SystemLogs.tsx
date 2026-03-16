import React, { useRef, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Info, AlertTriangle, ShieldAlert, XCircle } from 'lucide-react';

interface LogEntry {
  id: string;
  timestamp: number;
  type: 'info' | 'warn' | 'error' | 'attack';
  message: string;
}

interface Props {
  logs: LogEntry[];
}

export const SystemLogs: React.FC<Props> = ({ logs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isAutoScroll, setIsAutoScroll] = useState(true);

  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      const isBottom = scrollHeight - scrollTop - clientHeight < 50;
      setIsAutoScroll(isBottom);
    }
  };

  useEffect(() => {
    if (isAutoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, isAutoScroll]);

  const getIcon = (type: string) => {
    switch (type) {
      case 'info': return <Info size={12} className="text-blue-500" />;
      case 'warn': return <AlertTriangle size={12} className="text-yellow-500" />;
      case 'error': return <XCircle size={12} className="text-red-500" />;
      case 'attack': return <ShieldAlert size={12} className="text-red-600 animate-pulse" />;
      default: return <Terminal size={12} />;
    }
  };

  return (
    <div className="border border-[#141414] bg-[#141414] text-[#E4E3E0] h-full flex flex-col font-mono text-[10px]">
      <div className="p-2 border-b border-[#E4E3E0]/20 flex items-center justify-between bg-[#141414]">
        <div className="flex items-center gap-2">
          <Terminal size={14} />
          <span className="uppercase tracking-widest font-bold">系统控制台日志</span>
        </div>
        <div className="flex gap-1">
          <div className="w-2 h-2 rounded-full bg-red-500/50" />
          <div className="w-2 h-2 rounded-full bg-yellow-500/50" />
          <div className="w-2 h-2 rounded-full bg-green-500/50" />
        </div>
      </div>
      <div 
        ref={scrollRef} 
        onScroll={handleScroll}
        className="flex-grow overflow-y-auto p-2 space-y-1 custom-scrollbar"
      >
        <AnimatePresence initial={false}>
          {logs.length === 0 ? (
            <div className="opacity-30 italic p-4 text-center">等待系统事件...</div>
          ) : (
            logs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="flex gap-2 border-l border-[#E4E3E0]/10 pl-2 py-0.5 hover:bg-white/5 transition-colors"
              >
                <span className="opacity-30">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                <span className="flex items-center">{getIcon(log.type)}</span>
                <span className={`flex-grow ${log.type === 'attack' ? 'text-red-400 font-bold' : ''}`}>
                  {log.message}
                </span>
              </motion.div>
            ))
          )}
        </AnimatePresence>
      </div>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: rgba(255, 255, 255, 0.05);
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.2);
        }
      `}</style>
    </div>
  );
};
