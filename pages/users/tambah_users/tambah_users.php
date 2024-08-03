<?php
include './conf/conf.php'; // Include database connection file

// Check if user is an admin
if ($_SESSION['role'] !== 'admin') {
    echo "<script>
            window.onload = function() {
                Swal.fire({
                    icon: 'error',
                    title: 'Unauthorized Access',
                    text: 'You do not have permission to access this page.'
                }).then(function() {
                    window.location = '?q=users';
                });
            }
          </script>";
    exit;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $role = $_POST['role'];

    // Validate email domain
    if (!filter_var($username, FILTER_VALIDATE_EMAIL) || strpos($username, '@unima.ac.id') === false) {
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'error',
                        title: 'Invalid Email',
                        text: 'Invalid email domain. Please Use @unima.ac.id'
                    }).then(function() {
                        window.location = '?q=users';
                    });
                }
              </script>";
        exit;
    }

    // Insert user into the database
    $stmt = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $password, $role);
    if ($stmt->execute()) {
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'success',
                        title: 'Success',
                        text: 'User added successfully.'
                    }).then(function() {
                        window.location = '?q=users';
                    });
                }
              </script>";
    } else {
        echo "<script>
                window.onload = function() {
                    Swal.fire({
                        icon: 'error',
                        title: 'Error',
                        text: 'Error adding user.'
                    }).then(function() {
                        window.location = '?q=users';
                    });
                }
              </script>";
    }

    $stmt->close();
    $conn->close();
}