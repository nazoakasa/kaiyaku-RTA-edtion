// server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// メモリ内ストレージ（本番環境ではデータベースを使用）
const leaderboard = [];
const sessions = new Map();
const rateLimit = new Map();

app.use(cors());
app.use(express.json());

// セッション生成用のシークレット
const SECRET = process.env.SECRET_KEY || 'change-this-in-production';

// セッショントークン生成
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// HMAC署名生成
function generateSignature(data, secret) {
  return crypto.createHmac('sha256', secret)
    .update(JSON.stringify(data))
    .digest('hex');
}

// レート制限チェック
function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimit.get(ip) || { count: 0, resetTime: now + 3600000 };
  
  if (now > record.resetTime) {
    record.count = 0;
    record.resetTime = now + 3600000;
  }
  
  if (record.count >= 10) {
    return false;
  }
  
  record.count++;
  rateLimit.set(ip, record);
  return true;
}

// ゲーム開始エンドポイント
app.post('/api/start-session', (req, res) => {
  const ip = req.ip;
  
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  
  const sessionToken = generateSessionToken();
  const startTime = Date.now();
  
  sessions.set(sessionToken, {
    startTime,
    ip,
    completed: false
  });
  
  // 10分後に自動削除
  setTimeout(() => sessions.delete(sessionToken), 600000);
  
  res.json({ sessionToken, startTime });
});

// スコア送信エンドポイント
app.post('/api/submit-score', (req, res) => {
  const { sessionToken, playerName, finalTime, missCount, checkpoints, signature } = req.body;
  
  // バリデーション
  if (!sessionToken || !playerName || finalTime === undefined || !signature) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  // セッション検証
  const session = sessions.get(sessionToken);
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
  
  if (session.completed) {
    return res.status(400).json({ error: 'Session already used' });
  }
  
  // 署名検証
  const dataToSign = {
    sessionToken,
    playerName,
    finalTime,
    missCount,
    checkpoints
  };
  const expectedSignature = generateSignature(dataToSign, SECRET);
  
  if (signature !== expectedSignature) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // タイム検証
  const serverElapsed = Date.now() - session.startTime;
  const timeDiff = Math.abs(serverElapsed - finalTime);
  
  // サーバータイムとの差が10秒以上ある場合は不正
  if (timeDiff > 10000) {
    return res.status(400).json({ error: 'Time mismatch detected' });
  }
  
  // 異常に速いタイム（30秒未満）は疑わしい
  if (finalTime < 30000) {
    return res.status(400).json({ error: 'Suspicious time detected' });
  }
  
  // プレイヤー名のバリデーション
  if (playerName.length > 20 || playerName.length < 1) {
    return res.status(400).json({ error: 'Invalid player name length' });
  }
  
  // セッションを完了としてマーク
  session.completed = true;
  
  // スコアを保存
  const score = {
    id: crypto.randomBytes(8).toString('hex'),
    playerName: playerName.substring(0, 20), // サニタイズ
    finalTime,
    missCount: missCount || 0,
    checkpoints: checkpoints || [],
    timestamp: new Date().toISOString(),
    ip: session.ip // ログ用（表示はしない）
  };
  
  leaderboard.push(score);
  
  // ソートして上位100件のみ保持
  leaderboard.sort((a, b) => a.finalTime - b.finalTime);
  if (leaderboard.length > 100) {
    leaderboard.length = 100;
  }
  
  // ランキングを返す
  const rank = leaderboard.findIndex(s => s.id === score.id) + 1;
  
  res.json({
    success: true,
    rank,
    totalPlayers: leaderboard.length
  });
});

// リーダーボード取得エンドポイント
app.get('/api/leaderboard', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  
  const publicLeaderboard = leaderboard.slice(0, limit).map((score, index) => ({
    rank: index + 1,
    playerName: score.playerName,
    finalTime: score.finalTime,
    missCount: score.missCount,
    timestamp: score.timestamp
  }));
  
  res.json(publicLeaderboard);
});

// ヘルスチェック
app.get('/health', (req, res) => {
  res.json({ status: 'ok', sessions: sessions.size, scores: leaderboard.length });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
