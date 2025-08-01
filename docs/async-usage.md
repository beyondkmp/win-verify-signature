# 异步签名验证使用指南

## 概述

为了解决大文件签名验证时阻塞主线程的问题，我们添加了异步版本的签名验证功能。异步版本在后台线程中执行 `WinVerifyTrust` 操作，避免阻塞 Node.js 的事件循环。

## API 说明

### 异步函数

#### `verifySignatureByPublishNameAsync(filePath: string, publishNames: string[]): Promise<ISignStatus>`

这是主要的异步验证函数，返回一个 Promise。

**参数：**
- `filePath`: 要验证的文件路径
- `publishNames`: 允许的发布者名称列表

**返回值：**
- `Promise<ISignStatus>`: 包含签名验证结果的 Promise

#### `verifySignatureAsync(filePath: string): Promise<ISignStatus>` (底层函数)

底层的异步验证函数，直接调用原生 C++ 异步实现。

## 使用示例

### 基本异步使用

```typescript
import { verifySignatureByPublishNameAsync } from 'win-verify-signature';

async function verifyFile() {
  try {
    const result = await verifySignatureByPublishNameAsync(
      'C:\\path\\to\\large-file.exe',
      ['Microsoft Corporation']
    );
    
    console.log('签名验证结果:', result);
    console.log('是否已签名:', result.signed);
    console.log('验证消息:', result.message);
    console.log('签名主体:', result.subject);
  } catch (error) {
    console.error('验证失败:', error);
  }
}

verifyFile();
```

### 与原同步版本对比

```typescript
import { 
  verifySignatureByPublishName,      // 同步版本
  verifySignatureByPublishNameAsync  // 异步版本
} from 'win-verify-signature';

// 同步版本 - 会阻塞主线程
function syncVerify() {
  console.log('开始同步验证...');
  const result = verifySignatureByPublishName(
    'large-file.exe',
    ['Microsoft Corporation']
  );
  console.log('同步验证完成:', result);
}

// 异步版本 - 不会阻塞主线程
async function asyncVerify() {
  console.log('开始异步验证...');
  const result = await verifySignatureByPublishNameAsync(
    'large-file.exe',
    ['Microsoft Corporation']
  );
  console.log('异步验证完成:', result);
}

// 演示非阻塞特性
console.log('1. 开始');
asyncVerify();
console.log('2. 异步调用已启动，继续执行其他代码');
console.log('3. 主线程没有被阻塞');
```

### 批量文件验证

```typescript
import { verifySignatureByPublishNameAsync } from 'win-verify-signature';

async function verifyMultipleFiles(files: string[]) {
  const publishNames = ['Microsoft Corporation'];
  
  // 并行验证多个文件
  const promises = files.map(file => 
    verifySignatureByPublishNameAsync(file, publishNames)
  );
  
  try {
    const results = await Promise.all(promises);
    
    results.forEach((result, index) => {
      console.log(`文件 ${files[index]}:`);
      console.log(`  已签名: ${result.signed}`);
      console.log(`  消息: ${result.message}`);
      console.log('---');
    });
  } catch (error) {
    console.error('批量验证出错:', error);
  }
}

const filesToVerify = [
  'C:\\Windows\\System32\\notepad.exe',
  'C:\\Windows\\System32\\calc.exe',
  'C:\\Windows\\System32\\mspaint.exe'
];

verifyMultipleFiles(filesToVerify);
```

### 错误处理

```typescript
import { verifySignatureByPublishNameAsync } from 'win-verify-signature';

async function verifyWithErrorHandling(filePath: string) {
  try {
    const result = await verifySignatureByPublishNameAsync(
      filePath,
      ['Microsoft Corporation']
    );
    
    if (result.signed) {
      console.log('✅ 文件签名有效');
      console.log('签名主体:', result.subject);
    } else {
      console.log('❌ 文件签名无效或不存在');
      console.log('原因:', result.message);
    }
    
    return result;
  } catch (error) {
    if (error.message.includes('Accepted file types')) {
      console.error('❌ 不支持的文件类型');
    } else if (error.message.includes('Unable to locate')) {
      console.error('❌ 文件不存在');
    } else {
      console.error('❌ 验证过程中发生未知错误:', error.message);
    }
    throw error;
  }
}
```

## 性能对比

### 大文件处理

对于大文件（例如 > 100MB），异步版本的优势明显：

```typescript
// 同步版本 - 主线程被阻塞
console.time('sync-verify');
const syncResult = verifySignatureByPublishName('large-file.exe', ['Publisher']);
console.timeEnd('sync-verify');
// 输出: sync-verify: 5000ms (主线程被阻塞 5 秒)

// 异步版本 - 主线程继续工作
console.time('async-verify');
const asyncResult = await verifySignatureByPublishNameAsync('large-file.exe', ['Publisher']);
console.timeEnd('async-verify');
// 输出: async-verify: 5000ms (但主线程期间可以处理其他任务)
```

## 兼容性

- 异步版本与同步版本返回相同的结果格式
- 现有代码可以继续使用同步版本
- 建议新项目使用异步版本，特别是需要验证大文件时

## 技术实现

- 使用 N-API 的 `AsyncWorker` 在后台线程执行签名验证
- 支持 Promise 和 callback 两种调用方式
- 自动处理线程安全和资源清理
- 保持与原有 API 的完全兼容性

## 何时使用异步版本

**推荐使用异步版本的场景：**
- 验证大文件（> 50MB）
- 批量验证多个文件
- 在 Web 服务器中验证文件时
- 需要保持 UI 响应性的桌面应用

**可以继续使用同步版本的场景：**
- 小文件验证（< 10MB）
- 简单的命令行工具
- 不关心阻塞的脚本场景