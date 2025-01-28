<?php
require_once dirname(__FILE__) . '/private/conf.php';
session_start();

header("Location: index.php");
exit();


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    // Verificar token CSRF
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Token CSRF inválido.");
    }

    // Validación y saneamiento de entradas
    $username = trim($_POST['username']);
    if (strlen($username) < 3 || strlen($username) > 20) {
        die("El nombre de usuario debe tener entre 3 y 20 caracteres.");
    }
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        die("El nombre de usuario solo puede contener letras, números y guiones bajos.");
    }

    // Verificar si el usuario ya existe
    $checkQuery = "SELECT COUNT(*) FROM users WHERE username = :username";
    $checkStmt = $db->prepare($checkQuery);
    $checkStmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $checkStmt->execute();
    if ($result->fetchArray()[0] > 0) {
        die("El nombre de usuario ya existe.");
    }

    // Validar la contraseña
    if (strlen($_POST['password']) < 8) {
        die("La contraseña debe tener al menos 8 caracteres.");
    }

    // Hash de la contraseña
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    // Insertar nuevo usuario
    $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    
    if ($stmt->execute()) {
        header("Location: list_players.php");
        exit();
    } else {
        die("Error al registrar el usuario.");
    }
}

// Generar nuevo token CSRF para el formulario
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>
<!doctype html>
<html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Registro</title>
    </head>
    <body>
        <header>
            <h1>Register</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <label>Username:</label>
                <input type="text" name="username" required>
                <label>Password:</label>
                <input type="password" name="password" required>
                <input type="submit" value="Send">
            </form>
            <form action="#" method="post" class="menu-form">
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            &lt; Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a> &gt;
        </footer>
    </body>
</html>