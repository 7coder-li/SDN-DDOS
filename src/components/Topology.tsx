import React from 'react';

export const Topology: React.FC = () => {
  return (
    <svg viewBox="0 0 600 400" className="w-full h-full">
      {/* Links */}
      <line x1="300" y1="50" x2="150" y2="150" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="300" y1="50" x2="450" y2="150" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="150" y1="150" x2="100" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="150" y1="150" x2="200" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="450" y1="150" x2="350" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="450" y1="150" x2="400" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="450" y1="150" x2="450" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />
      <line x1="450" y1="150" x2="500" y2="250" stroke="#141414" strokeWidth="2" strokeDasharray="4,4" />

      {/* Nodes */}
      {/* Switches */}
      <circle cx="300" cy="50" r="15" fill="#141414" />
      <text x="320" y="55" fontSize="12" fontWeight="bold">s1</text>
      
      <circle cx="150" cy="150" r="15" fill="#141414" />
      <text x="170" y="155" fontSize="12" fontWeight="bold">s2</text>
      
      <circle cx="450" cy="150" r="15" fill="#141414" />
      <text x="470" y="155" fontSize="12" fontWeight="bold">s3</text>

      {/* Hosts */}
      <circle cx="100" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="115" y="255" fontSize="10">h_u1</text>
      
      <circle cx="200" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="215" y="255" fontSize="10">h_u2</text>
      
      <circle cx="350" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="365" y="255" fontSize="10">h_a1</text>
      
      <circle cx="400" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="415" y="255" fontSize="10">h_a2</text>
      
      <circle cx="450" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="465" y="255" fontSize="10">h_a3</text>
      
      <circle cx="500" cy="250" r="8" fill="white" stroke="#141414" strokeWidth="2" />
      <text x="515" y="255" fontSize="10">h_v</text>
    </svg>
  );
};
