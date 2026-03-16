import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from 'url';
import fetch from "node-fetch";
import dotenv from "dotenv";
import fs from "fs";
import { initMLEngine, predict } from './src/mlEngine';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log(`📂 [Config] CWD: ${process.cwd()}`);
const envPath = path.resolve(process.cwd(), ".env");
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, "utf-8");
  console.log("📄 [Config] .env file found. Content length:", envContent.length);
  envContent.split("\n").forEach(line => {
    const [key, ...valueParts] = line.split("=");
    if (key && valueParts.length > 0) {
      const value = valueParts.join("=").replace(/["']/g, "").trim();
      process.env[key.trim()] = value;
      console.log(`✅ [Config] Set ${key.trim()} from .env`);
    }
  });
} else {
  console.log("❌ [Config] .env file NOT found at", envPath);
}

dotenv.config(); // Still call it just in case

console.log("🛠️ [Config] Environment variables loaded.");
console.log(`🔗 [Config] RYU_CONTROLLER_URL: ${process.env.RYU_CONTROLLER_URL || "NOT SET"}`);

async function startServer() {
  // 1. 初始化 ML 引擎
  await initMLEngine();

  const app = express();
  const PORT = 3000;

  console.log("🛠️ [Config] RYU_CONTROLLER_URL:", process.env.RYU_CONTROLLER_URL || "NOT SET");

  app.use(express.json());

  // --- 状态存储 ---
  let blockedFlows: Set<string> = new Set(); // 存储被拦截的流量特征 (src-dst)
  let activeAttacks: Set<string> = new Set(); // 存储正在进行的攻击类型
  let lastFlowStats: Map<string, { packets: number, time: number, lastPps?: number }> = new Map();
  let lastLoggedAttack: Map<string, number> = new Map(); // 记录上次记录攻击日志的时间，防止刷屏
  let systemLogs: { id: string, timestamp: number, type: 'info' | 'warn' | 'error' | 'attack', message: string }[] = [];
  let persistentHosts: Set<string> = new Set(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]);

  const addLog = (type: 'info' | 'warn' | 'error' | 'attack', message: string) => {
    const log = { id: Math.random().toString(36).substr(2, 9), timestamp: Date.now(), type, message };
    systemLogs.push(log);
    if (systemLogs.length > 50) systemLogs.shift();
    console.log(`[LOG] ${type.toUpperCase()}: ${message}`);
  };

  addLog('info', 'SDN 安全监控系统已启动');

  // --- 本地机器学习模型 ---
  const classifyTraffic = async (features: any) => {
    try {
      // 特征顺序必须与训练时一致:
      // ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Total Backward Packets', 'Total Length of Bwd Packets', 'Average Packet Size']
      const featureArray = [
        features['Protocol'] || 0,
        features['Flow Duration'] || 0,
        features['Total Fwd Packets'] || 0,
        features['Total Length of Fwd Packets'] || 0,
        features['Total Backward Packets'] || 0,
        features['Total Length of Bwd Packets'] || 0,
        features['Average Packet Size'] || 0
      ];
      
      const isAttack = await predict(featureArray);
      const isAttackBool = isAttack === 1;
      const attackProbability = 0.95; // 简化概率

      let attackType = "DDoS_ATTACK";
      if (isAttackBool) {
          // 根据特征推断具体的攻击类型，以便前端显示
          const proto = features['Protocol'];
          const avgSize = features['Average Packet Size'];
          if (proto === 6 && avgSize < 120) attackType = "SYN_FLOOD";
          else if (proto === 17 && avgSize < 1000) attackType = "UDP_FLOOD";
          else if (proto === 17 && avgSize >= 1000) attackType = "DNS_REFLECTION";
          else if (proto === 6 && avgSize >= 1000) attackType = "HTTP_FLOOD";
      }
      return {
        type: isAttackBool ? attackType : "NORMAL",
        confidence: attackProbability
      };
    } catch (e) {
      console.error("[ML Engine] 推理失败:", e);
      return { type: "NORMAL", confidence: 0 };
    }
  };

  const ATTACK_CONFIGS: Record<string, any> = {
    'SYN_FLOOD': { 
      src: "10.0.0.1", 
      dst: "10.0.0.100", 
      pps: 15000, 
      avgSize: 64,
      host: "h_a1",
      startCmd: "hping3 -S -p 80 --flood 10.0.0.100",
      stopCmd: "pkill -f hping3"
    },
    'UDP_FLOOD': { 
      src: "10.0.0.2", 
      dst: "10.0.0.100", 
      pps: 12000, 
      avgSize: 512,
      host: "h_a2",
      startCmd: "hping3 --udp -p 53 --flood 10.0.0.100",
      stopCmd: "pkill -f hping3"
    },
    'DNS_REFLECTION': { 
      src: "10.0.0.3", 
      dst: "10.0.0.100", 
      pps: 8000, 
      avgSize: 1024,
      host: "h_a3",
      startCmd: "hping3 --udp -p 53 -d 1000 --flood 10.0.0.100",
      stopCmd: "pkill -f hping3"
    },
    'HTTP_FLOOD': { 
      src: "10.0.0.4", 
      dst: "10.0.0.100", 
      pps: 3000, 
      avgSize: 1460,
      host: "h_a4",
      startCmd: "hping3 -S -p 80 -d 1200 --flood 10.0.0.100", // Use hping3 with large payload to simulate HTTP
      stopCmd: "pkill -f hping3"
    },
  };

  const sendMininetCommand = async (host: string, command: string) => {
    const MININET_URL = process.env.MININET_CONTROL_URL || "http://127.0.0.1:5000";
    addLog('info', `向 Mininet 发送指令 [${host}]: ${command}`);
    try {
      const response = await fetch(`${MININET_URL}/command`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, command })
      });
      
      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${text.substring(0, 100)}`);
        }
        throw new Error(`Invalid JSON response: ${text.substring(0, 100)}`);
      }
      
      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      addLog('info', `Mininet 响应 [${host}]: ${JSON.stringify(data)}`);
      return data;
    } catch (e: any) {
      addLog('error', `Mininet 指令执行失败: ${e.message}`);
      return { error: e.message };
    }
  };

  // --- API 路由 ---
  app.get("/api/stats", async (req, res) => {
    console.log("📡 [API] /api/stats requested");
    const RYU_URL = process.env.RYU_CONTROLLER_URL || "http://127.0.0.1:8080";
    
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      
      const [swRes] = await Promise.all([
        fetch(`${RYU_URL}/stats/switches`, { signal: controller.signal }).catch(() => null)
      ]);
      clearTimeout(timeout);

      const dpids = swRes && swRes.ok ? await swRes.json() : [];

      if (dpids.length > 0) {
        // console.log(`🌐 [Topology] Found ${dpids.length} switches.`);
      }

      // 获取所有交换机的流表
      const flowPromises = dpids.map((dpid: number) => 
        fetch(`${RYU_URL}/stats/flow/${dpid}`, { signal: controller.signal })
          .then(r => r.json())
          .catch(() => ({}))
      );
      const allRyuFlows = await Promise.all(flowPromises);
      
      // 合并所有流表
      let rawFlows: any[] = [];
      allRyuFlows.forEach(f => {
        const dpid = Object.keys(f)[0];
        if (dpid && f[dpid]) rawFlows = [...rawFlows, ...f[dpid]];
      });

      if (rawFlows.length > 0) {
        // console.log(`✅ [Ryu] Fetched ${rawFlows.length} raw flows from ${dpids.length} switches.`);
      }

      const now = Date.now();

      // 聚合流表 (按 src-dst)，防止多条同源同目的流表互相覆盖导致 PPS 爆炸
      const flowMap = new Map<string, { packets: number, bytes: number, src: string, dst: string, isBlocked: boolean }>();
      
      rawFlows.forEach((f: any) => {
        if (!f.match) return;
        let rawSrc = f.match.ipv4_src || f.match.nw_src || f.match.eth_src || f.match.dl_src;
        let rawDst = f.match.ipv4_dst || f.match.nw_dst || f.match.eth_dst || f.match.dl_dst;
        if (!rawSrc || !rawDst) return;
        
        // 过滤掉广播、组播、STP、LLDP 等底层噪音流量
        if (rawDst === 'ff:ff:ff:ff:ff:ff' || rawDst.startsWith('01:80:c2') || rawDst.startsWith('33:33') || rawDst.startsWith('01:00:5e')) {
          return;
        }

        const macToIp = (mac: string) => {
          if (mac && mac.startsWith('00:00:00:00:00:')) {
            const hex = mac.split(':').pop();
            if (hex) return `10.0.0.${parseInt(hex, 16)}`;
          }
          return mac;
        };

        const src = macToIp(rawSrc);
        const dst = macToIp(rawDst);
        const key = `${src}-${dst}`;
        const proto = f.match.ip_proto || f.match.nw_proto || 6;

        const packets = parseInt(f.packet_count) || 0;
        const bytes = parseInt(f.byte_count) || 0;
        const duration_sec = parseInt(f.duration_sec) || 0;
        const duration_nsec = parseInt(f.duration_nsec) || 0;
        const durationUs = duration_sec * 1000000 + duration_nsec / 1000;
        const isBlocked = blockedFlows.has(key) || f.priority === 65535;

        if (flowMap.has(key)) {
          const existing = flowMap.get(key)!;
          existing.packets += packets;
          existing.bytes += bytes;
          existing.duration = Math.max(existing.duration || 0, durationUs);
          existing.isBlocked = existing.isBlocked || isBlocked;
          existing.proto = proto;
        } else {
          flowMap.set(key, { packets, bytes, src, dst, isBlocked, proto, duration: durationUs });
        }
      });

      let processedFlows = Array.from(flowMap.values()).map((flow) => {
        const key = `${flow.src}-${flow.dst}`;
        const last = lastFlowStats.get(key);
        let pps = 0;
        
        if (last) {
          const timeDiff = (now - last.time) / 1000;
          if (timeDiff >= 1.0) { 
            // 至少间隔 1 秒才重新计算，防止 React StrictMode 或多标签页导致的极小 timeDiff 引起 PPS 爆炸
            pps = Math.max(0, (flow.packets - last.packets) / timeDiff);
            lastFlowStats.set(key, { packets: flow.packets, time: now, lastPps: pps });
          } else {
            // 间隔太短，复用上次的 PPS，不更新时间，等待下一次轮询
            pps = last.lastPps || 0;
          }
        } else {
          // 第一次获取该流表，无法计算瞬时速率，记为 0，等待下一次轮询计算真实的增量
          pps = 0;
          lastFlowStats.set(key, { packets: flow.packets, time: now, lastPps: 0 });
        }

        const avgSize = flow.packets > 0 ? flow.bytes / flow.packets : 64;
        const flowDurationUs = flow.duration > 0 ? flow.duration : 1000000.0; // 避免除以 0
        
        // 构造完全符合 CICDDoS2019 数据集格式的特征
        // 数据集中的特征是基于整个流的生命周期的累计值，而不是瞬时速率
        const features = {
          'Protocol': flow.proto,
          'Flow Duration': flowDurationUs, 
          'Total Fwd Packets': flow.packets, // 累计发包数
          'Total Length of Fwd Packets': flow.bytes, // 累计字节数
          'Total Backward Packets': 0, // 简化处理，假设攻击流单向
          'Total Length of Bwd Packets': 0,
          'Average Packet Size': avgSize
        };
        const classificationPromise = classifyTraffic(features);
        const isActive = pps > 0.001; // 进一步降低阈值，捕捉极其微弱的流量

        // 发现新主机
        if (flow.src && flow.src.length > 5 && !flow.src.startsWith('Port-') && !persistentHosts.has(flow.src)) {
          persistentHosts.add(flow.src);
          addLog('info', `发现新主机节点: ${flow.src}`);
        }
        if (flow.dst && flow.dst.length > 5 && flow.dst !== "ANY" && !persistentHosts.has(flow.dst)) {
          persistentHosts.add(flow.dst);
          addLog('info', `发现新主机节点: ${flow.dst}`);
        }

        return classificationPromise.then(classification => ({
          id: key,
          src: flow.src,
          dst: flow.dst,
          pps: Math.floor(pps),
          bps: Math.floor(pps * avgSize * 8),
          type: classification.type,
          confidence: classification.confidence,
          status: flow.isBlocked ? "blocked" : (isActive ? "active" : "idle"),
          isMalicious: classification.type !== "NORMAL"
        }));
      });

      processedFlows = await Promise.all(processedFlows);

      // 过滤往返流量，只保留单向流量（PPS 较大的那个），防止 ping/hping3 显示两条
      processedFlows = processedFlows.filter((flow: any, index: number, self: any[]) => {
        // 如果是被拦截的流量，强制保留，否则可能导致拦截状态显示异常
        if (flow.status === 'blocked') return true;
        
        const reverseKey = `${flow.dst}-${flow.src}`;
        const reverseFlow = self.find(f => f.src === flow.dst && f.dst === flow.src);
        
        // 如果存在反向流量，且反向流量的 PPS 更大，则隐藏当前流量
        if (reverseFlow && flow.pps < reverseFlow.pps) return false; 
        
        // 如果 PPS 相等，保留 index 较小的那个，防止两个都被过滤掉
        if (reverseFlow && flow.pps === reverseFlow.pps && index > self.indexOf(reverseFlow)) return false;
        
        return true;
      });

      // 记录攻击日志（在过滤掉反向流量之后，避免日志中出现双向攻击）
      processedFlows.forEach((flow: any) => {
        if (flow.isMalicious && flow.status === 'active') {
          const logKey = `${flow.type}-${flow.src}-${flow.dst}`;
          const lastLogged = lastLoggedAttack.get(logKey) || 0;
          if (now - lastLogged > 3000) { // 同一类型的攻击至少间隔 3 秒才重复记录
            addLog('attack', `检测到潜在攻击: ${flow.type} 来自 ${flow.src} -> ${flow.dst} (置信度: ${(flow.confidence * 100).toFixed(1)}%)`);
            lastLoggedAttack.set(logKey, now);
          }
        }
      });

      if (processedFlows.length > 0) {
        console.log(`📊 [Flows] Processed ${processedFlows.length} active/idle flows.`);
      }

      const totalThroughput = processedFlows
        .filter(f => f.status === "active")
        .reduce((sum, f) => sum + f.bps, 0);

      const hosts = Array.from(persistentHosts).map(ip => ({ ip }));

      if (hosts.length > 0) {
        // console.log(`🏠 [Topology] Discovered ${hosts.length} hosts.`);
      }

      res.json({
        flows: processedFlows,
        activeAttacks: Array.from(activeAttacks), // 必须返回这个，否则前端按钮状态会重置
        topology: {
          switches: [{ dpid: "1" }, { dpid: "2" }, { dpid: "3" }],
          links: [{ src: "1", dst: "2" }, { src: "1", dst: "3" }],
          hosts: [
            { ip: "10.0.0.1" }, { ip: "10.0.0.2" }, { ip: "10.0.0.3" }, 
            { ip: "10.0.0.4" }, { ip: "10.0.0.100" }
          ]
        },
        metrics: {
          throughput: totalThroughput,
          attackCount: processedFlows.filter(f => f.isMalicious && f.status === "active").length
        }
      });
      // console.log(`📤 [API] Stats sent to frontend.`);
    } catch (error: any) {
      console.warn(`⚠️ [API] Ryu connection failed, using fallback mode: ${error.message}`);
      // 彻底的降级模式
      res.json({ 
        flows: [], 
        activeAttacks: Array.from(activeAttacks),
        topology: { switches: [{ dpid: "1" }], links: [], hosts: [{ ip: "10.0.0.1" }] }, 
        metrics: { throughput: 0, attackCount: 0 } 
      });
    }
  });

  app.get("/api/logs", (req, res) => {
    res.json(systemLogs);
  });

  app.post("/api/control/block", async (req, res) => {
    const { src, dst, block } = req.body;
    const RYU_URL = process.env.RYU_CONTROLLER_URL || "http://127.0.0.1:8080";
    const key = `${src}-${dst}`;

    try {
      if (block) {
        blockedFlows.add(key);
        addLog('warn', `手动拦截流量: ${key}`);
        await fetch(`${RYU_URL}/stats/flowentry/add`, {
          method: "POST",
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dpid: 1,
            priority: 65535,
            match: { eth_type: 2048, ipv4_src: src, ipv4_dst: dst },
            actions: [] 
          })
        }).catch(err => addLog('error', `Ryu 拦截指令发送失败: ${err.message}`));
      } else {
        blockedFlows.delete(key);
        addLog('info', `解除流量拦截: ${key}`);
        await fetch(`${RYU_URL}/stats/flowentry/delete_strict`, {
          method: "POST",
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dpid: 1,
            priority: 65535,
            match: { eth_type: 2048, ipv4_src: src, ipv4_dst: dst }
          })
        }).catch(err => addLog('error', `Ryu 解除拦截指令发送失败: ${err.message}`));
      }
      res.json({ success: true });
    } catch (e) {
      res.json({ success: true, warning: "Ryu communication failed, state updated locally" });
    }
  });

  app.post("/api/control/attack", async (req, res) => {
    const { type, active } = req.body;
    const config = ATTACK_CONFIGS[type];
    const RYU_URL = process.env.RYU_CONTROLLER_URL || "http://127.0.0.1:8080";
    const MININET_URL = process.env.MININET_CONTROL_URL || "http://127.0.0.1:5000";

    if (active) {
      activeAttacks.add(type);
      console.log(`🔥 [Control] Attack STARTED: ${type}`);
      if (config) {
        await sendMininetCommand(config.host, config.startCmd);
        
        // 延迟一秒后获取 Mininet API 的执行日志，以便在前端显示错误
        setTimeout(async () => {
            try {
                const logRes = await fetch(`${MININET_URL}/logs`);
                if (logRes.ok) {
                    const logData = await logRes.json();
                    if (logData.logs && logData.logs.includes('[ERROR]')) {
                        // 提取最后一条错误信息
                        const lines = logData.logs.split('\n');
                        const lastError = lines.reverse().find((l: string) => l.includes('[ERROR]'));
                        if (lastError) {
                            addLog('error', `Mininet 执行失败: ${lastError.replace(/\[ERROR\]\s*/, '')}`);
                        }
                    }
                }
            } catch (e) {
                // 忽略获取日志失败的错误
            }
        }, 1500);
      }
    } else {
      activeAttacks.delete(type);
      console.log(`❄️ [Control] Attack STOPPED: ${type}`);
      if (config) {
        await sendMininetCommand(config.host, config.stopCmd);
        
        // 自动解除拦截，防止残留的流表导致 pingall 失败
        const key = `${config.src}-${config.dst}`;
        if (blockedFlows.has(key)) {
          blockedFlows.delete(key);
          addLog('info', `自动解除流量拦截: ${key} (攻击已停止)`);
          await fetch(`${RYU_URL}/stats/flowentry/delete_strict`, {
            method: "POST",
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              dpid: 1,
              priority: 65535,
              match: { eth_type: 2048, ipv4_src: config.src, ipv4_dst: config.dst }
            })
          }).catch(err => console.error(`Failed to auto-unblock: ${err.message}`));
        }
      }
    }
    res.json({ success: true });
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 SDN Backend Ready on port ${PORT}`);
    console.log(`📡 [API] Stats requested. RYU_URL: ${process.env.RYU_CONTROLLER_URL || "http://127.0.0.1:8080"}`);
  });
}

startServer().catch(err => {
  console.error("❌ [FATAL] Server failed to start:", err);
});
