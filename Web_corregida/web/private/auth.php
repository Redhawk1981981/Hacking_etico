<?php
ob_start();
require_once dirname(__FILE__) . '/conf.php';

session_start();

function sanitize_string($string) {
    return preg_replace('/[^A-Za-z0-9\-_]/', '', $string);
}

# Check whether a pair of user and password are valid; returns true if valid.
function areUserAndPasswordValid($user, $password) {
    global $db;

    $user = sanitize_string($user);
    if (!$user || strlen($user) < 3 || strlen($user) > 20) {
        return FALSE;
    }

    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();

    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) return FALSE;

    if ($password === $row['password']) {
        $_SESSION['userId'] = $row['userId'];
        $_SESSION['username'] = $user;
        $_SESSION['last_activity'] = time();
        session_regenerate_id(true);
        return TRUE;
    } else {
        return FALSE;
    }
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function logout() {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
}

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

$login_ok = FALSE;
$error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['Logout'])) {
        logout();
        header("Location: index.php");
        exit();
    } elseif (isset($_POST['username']) && isset($_POST['password'])) {
        if ($_SESSION['login_attempts'] >= 5) {
            $error = "Demasiados intentos fallidos. Por favor, inténtelo más tarde.";
        } elseif (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            $error = "Token CSRF inválido.";
        } else {
            if (areUserAndPasswordValid($_POST['username'], $_POST['password'])) {
                $login_ok = TRUE;
                $_SESSION['login_attempts'] = 0;
            } else {
                $login_ok = FALSE;
                $_SESSION['login_attempts']++;
                $error = "Usuario o contraseña inválidos.";
                sleep(1); // Retraso para prevenir ataques de fuerza bruta
            }
        }
    }
}

if (isset($_SESSION['userId'])) {
    $login_ok = TRUE;
    if (time() - $_SESSION['last_activity'] > 1800) {
        logout();
        $login_ok = FALSE;
        $error = "La sesión ha expirado. Por favor, inicie sesión nuevamente.";
    } else {
        $_SESSION['last_activity'] = time();
    }
}

if ($login_ok == FALSE) {
    $csrf_token = generateCSRFToken();
?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="../css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <label>User</label>
                    <input type="text" name="username" required minlength="3" maxlength="20" pattern="[a-zA-Z0-9_-]+"><br>
                    <label>Password</label>
                    <input type="password" name="password" required><br>
                    <input type="submit" value="Login">
                </form>
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        &lt; Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> &gt;
    </footer>
    </body>
    </html>
    <?php
    exit(0);
}
ob_end_flush();
?>