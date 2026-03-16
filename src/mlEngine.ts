import { InferenceSession, Tensor } from 'onnxruntime-node';
import fs from 'fs';
import path from 'path';

let session: InferenceSession;
let scalerParams: { mean: number[], scale: number[] };

// 加载模型和参数
export async function initMLEngine() {
  const modelPath = path.join(process.cwd(), 'model.onnx');
  const scalerPath = path.join(process.cwd(), 'scaler_params.json');
  
  if (!fs.existsSync(modelPath) || !fs.existsSync(scalerPath)) {
    console.warn("⚠️ [ML Engine] 模型文件不存在，跳过初始化。请确保已生成 model.onnx 和 scaler_params.json");
    return;
  }

  session = await InferenceSession.create(modelPath);
  console.log("✅ [ML Engine] 初始化完成, 输出名称:", session.outputNames);
  scalerParams = JSON.parse(fs.readFileSync(scalerPath, 'utf-8'));
  console.log("✅ [ML Engine] 参数加载完成");
}

// 预处理：标准化 (x - mean) / scale
function preprocess(features: number[]): Float32Array {
  return new Float32Array(features.map((x, i) => (x - scalerParams.mean[i]) / scalerParams.scale[i]));
}

// 推理
export async function predict(features: number[]): Promise<number> {
  if (!session) throw new Error("ML 引擎未初始化");

  const inputData = preprocess(features);
  const inputTensor = new Tensor('float32', inputData, [1, 7]);
  
  // 关键修复：只请求第一个输出，避免处理复杂的非 Tensor 输出
  const tensorOutputName = session.outputNames[0];
  if (!tensorOutputName) {
      throw new Error("模型中未找到可用的输出");
  }

  // 明确只请求这一个输出
  const outputData = await session.run({ float_input: inputTensor }, [tensorOutputName]);
  
  const result = outputData[tensorOutputName];
  
  if (result && 'data' in result) {
      return Number(result.data[0]);
  } else {
      throw new Error("无法从输出中提取数据");
  }
}
