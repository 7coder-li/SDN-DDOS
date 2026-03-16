export interface Flow {
  id: string;
  src: string;
  dst: string;
  pps: number;
  bps: number;
  type: string;
  status: "active" | "blocked" | "idle";
  isMalicious: boolean;
  confidence: number;
}

export interface TopologyData {
  switches: { dpid: string }[];
  links: { src: string; dst: string }[];
  hosts: { ip: string }[];
}

export interface TrafficStats {
  timestamp: number;
  packetRate: number;
  byteRate: number;
  activeFlows: number;
}

export interface DetectionResult {
  isAttack: boolean;
  confidence: number;
  reason?: string;
  attackers?: { ip: string; confidence: number; reason: string }[];
}
