<html>
 <head>
 	<title>SQL injection</title>
 	<style>
 		body{
 		}
 		.user {
 			background-color: yellow;
 		}
 	</style>
 </head>
 
 <body>
 	<h1>PDO vulnerable a SQL injection</h1>
 
<?php

if (isset($_POST["user"])) {

    $dbhost = $_ENV["DB_HOST"];
    $dbname = $_ENV["DB_NAME"];
    $dbuser = $_ENV["DB_USER"];
    $dbpass = $_ENV["DB_PASSWORD"];

    try {
        $pdo = new PDO("mysql:host=$dbhost;dbname=$dbname", $dbuser, $dbpass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $username = $_POST["user"];
        $password = $_POST["password"];

        // Consulta preparada para evitar la inyección SQL
        $stmt = $pdo->prepare("SELECT * FROM users WHERE name=:username AND password=SHA2(:password, 512)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':password', $password);
        $stmt->execute();

        // Verificar si se encontró un usuario
        if ($stmt->rowCount() >= 1) {
            // Usuario autenticado correctamente
            foreach ($stmt as $user) {
                echo "<div class='user'>Hola ".$user["name"]." (".$user["role"].").</div>";
            }
        } else {
            echo "<div class='user'>No hay ningún usuario con este nombre o contraseña.</div>";
        }
    } catch(PDOException $e) {
        // Manejo de errores de conexión o consulta
        echo "<p>ERROR: ".$e->getMessage()."</p>\n";
        die;
    }
}

?>

 	
 	<fieldset>
 	<legend>Login form</legend>
  	<form method="post">
		User: <input type="text" name="user" /><br>
		Pass: <input type="text" name="password" /><br>
		<input type="submit" /><br>
 	</form>
  	</fieldset>
	
 </body>
 
 </html>
