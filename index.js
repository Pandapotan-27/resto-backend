require("dotenv").config();
const express = require("express");
const cors = require("cors");

const authRoutes = require("./routes/authRoutes");
const authenticate = require("./middleware/authenticate");

const app = express();

// Middleware
app.use(
  cors({
    exposedHeaders: ["X-Access-Token", "X-Token-Refreshed"]
  })
);
app.use(express.json());

// Endpoint utama
app.get("/", (req, res) => {
  res.json({
    message: "Taste of Nusantara backend berjalan"
  });
});

// Route Auth
app.use("/api/auth", authRoutes);

// Semua endpoint API selain route autentikasi wajib memakai Bearer token
app.use("/api", authenticate);

// Endpoint tidak ditemukan (404)
app.use((req, res) => {
  res.status(404).json({
    message: "Endpoint tidak ditemukan"
  });
});

// Menjalankan server secara lokal
if (require.main === module) {
  const PORT = process.env.PORT || 2000;

  app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
  });
}

// Export untuk Vercel
module.exports = app;