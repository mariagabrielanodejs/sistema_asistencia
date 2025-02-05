const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.MYSQL_ADDON_HOST,
  user: process.env.MYSQL_ADDON_USER,
  password: process.env.MYSQL_ADDON_PASSWORD,
  database: process.env.MYSQL_ADDON_DB,
  port: process.env.MYSQL_ADDON_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


const checkConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Conectado a MySQL');
    connection.release();
  } catch (error) {
    console.error('❌ Error de conexión a MySQL:', error.message);
    process.exit(1);
  }
};

checkConnection();

module.exports = pool;