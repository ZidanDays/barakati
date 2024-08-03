<div class="container">
    <div class="page-inner">
        <div class="d-flex align-items-left align-items-md-center flex-column flex-md-row pt-2 pb-4">
            <div>
                <h3 class="fw-bold mb-3">Ganti Foto Profil Anda</h3>
                <h6 class="op-7 mb-2">Monitoring Page - See The Monitoring System</h6>
            </div>
            <div class="ms-md-auto py-2 py-md-0">
                <a href="?q=beranda" class="btn btn-primary btn-round">Dashboard</a>
            </div>
        </div>

        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card card-round">
                    <div class="card-header">
                        <div class="card-head-row">
                            <div class="card-title">Ganti Foto Profil Anda</div>
                        </div>
                    </div>
                    <div class="card-body">
                        <form action="?q=up_profile" method="post" enctype="multipart/form-data" id="uploadForm">
                            <div class="form-group">
                                <label for="profile_pic">Pilih Foto Profil:</label>
                                <input type="file" name="profile_pic" id="profile_pic" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary btn-round mt-3">Upload</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6">
                <div class="card card-round">
                    <div class="card-header">
                        <div class="card-head-row">
                            <div class="card-title">Preview Foto Profil</div>
                        </div>
                    </div>
                    <div class="card-body text-center">
                        <img id="previewImage" src="#" style="max-width: 100%; max-height: 300px;">
                        <p id="imagePlaceholder" class="mt-2 text-muted">Belum ada foto. Silahkan pilih.</p>
                    </div>
                </div>
            </div>

            <script>
                document.addEventListener("DOMContentLoaded", function() {
                    // Preview image when file is selected
                    document.getElementById("profile_pic").addEventListener("change", function() {
                        const reader = new FileReader();

                        reader.onload = function(e) {
                            document.getElementById("previewImage").setAttribute("src", e.target
                                .result);
                            document.getElementById("imagePlaceholder").style.display =
                                "none"; // Sembunyikan teks placeholder
                        };

                        reader.readAsDataURL(this.files[0]);
                    });

                    // Tampilkan teks placeholder jika tidak ada gambar yang dipilih
                    document.getElementById("profile_pic").addEventListener("input", function() {
                        if (!this.value) {
                            document.getElementById("previewImage").setAttribute("src", "#");
                            document.getElementById("imagePlaceholder").style.display =
                                "block"; // Tampilkan teks placeholder
                        }
                    });
                });
            </script>


        </div>
    </div>
</div>