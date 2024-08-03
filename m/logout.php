<?php
session_start();

// Log activity
include '../conf/conf.php';
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $activity = "User logged out";
    $log_stmt = $conn->prepare("INSERT INTO log_activity (user_id, activity) VALUES (?, ?)");
    $log_stmt->bind_param("is", $user_id, $activity);
    $log_stmt->execute();
    $log_stmt->close();
    $conn->close();
}

// Unset all of the session variables
$_SESSION = array();

// Destroy the session
session_destroy();

// Redirect to login page
header("Location: ../login");
exit;
