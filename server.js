const app = require('./api/index.js');
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(`🔒 VaultDrop Cloud Text Server Running!`);
  console.log(`📍 Local:   http://localhost:${PORT}`);
  console.log(`🌐 Network: http://0.0.0.0:${PORT}`);
  console.log(`===============================================`);
});
