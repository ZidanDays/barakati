<?php
session_start();
include '../conf/conf.php'; // Include database connection file

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validate email domaind
    if (!filter_var($username, FILTER_VALIDATE_EMAIL) || strpos($username, '@unima.ac.id') === false) {
        echo "Invalid email domain.";
        exit;
    }

    // Check if user exists in the database
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        // Verify the hashed password
        if (password_verify($password, $user['password'])) {
            // Set session variables
            $_SESSION['username'] = $username;
            $_SESSION['role'] = $user['role'];
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['profile_pic'] = $user['profile_pic'];

            // Log activity
            $activity = "User logged in";
            $log_stmt = $conn->prepare("INSERT INTO log_activity (user_id, activity) VALUES (?, ?)");
            $log_stmt->bind_param("is", $user['id'], $activity);
            $log_stmt->execute();
            $log_stmt->close();

            // Redirect based on user role
            switch ($user['role']) {
                case 'admin':
                    header("Location: ../my");
                    break;
                case 'ketua_kelas':
                    header("Location: ../kt");
                    break;
                case 'dosen':
                    header("Location: ../d");
                    break;
                case 'mahasiswa':
                    header("Location: ../m");
                    break;
                default:
                    echo "Invalid user role.";
                    exit;
            }
        } else {
            echo "Incorrect password.";
        }
    } else {
        echo "No user found with this username.";
    }

    $stmt->close();
    $conn->close();
}
