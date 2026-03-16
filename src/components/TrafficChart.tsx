import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { TrafficStats } from '../types';

interface Props {
  data: TrafficStats[];
}

export const TrafficChart: React.FC<Props> = ({ data }) => {
  return (
    <div className="h-64 w-full bg-[#E4E3E0] border border-[#141414] p-4">
      <h3 className="text-[11px] font-serif italic uppercase tracking-wider mb-4 opacity-50">网络吞吐量 (包/秒)</h3>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#141414" strokeOpacity={0.1} />
          <XAxis 
            dataKey="timestamp" 
            hide 
          />
          <YAxis 
            stroke="#141414" 
            fontSize={10} 
            tickFormatter={(value) => `${value}`}
          />
          <Tooltip 
            contentStyle={{ backgroundColor: '#141414', color: '#E4E3E0', border: 'none', fontFamily: 'Courier New', fontSize: '10px' }}
            itemStyle={{ color: '#E4E3E0' }}
          />
          <Line 
            type="monotone" 
            dataKey="packetRate" 
            stroke="#141414" 
            strokeWidth={2} 
            dot={false} 
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};
