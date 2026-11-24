
const express = require("express");
const supabase = require("./config/supabase");
const menuRoutes = require("./routes/menuRoutes");


const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use("/api/menu", menuRoutes);

// Halaman utama untuk mengecek server
app.get("/", (req, res) => {
    res.send("Backend Taste of Nusantara berjalan!");
});

// Mengecek koneksi Supabase
app.get("/test-db", async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("menu")
            .select("id")
            .limit(1);

        if (error) {
            throw error;
        }

        res.status(200).json({
            message: "Supabase berhasil terhubung!",
            data: data
        });

    } catch (error) {
        res.status(500).json({
            message: "Koneksi Supabase gagal",
            error: error.message
        });
    }
});

// Menjalankan server
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
