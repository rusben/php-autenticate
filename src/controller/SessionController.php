<?php


class SessionController {

    private $connection;

    public function __construct() {
        $this->connection = DatabaseController::connect();
    }

    public static function userSignUp($username, $email, $password) {

        if ((new self)->exist($username, $email)) {
            echo "Username or email already exist";
            return;
        } else {
            try  {
       
                $sql = "INSERT INTO User
                        (username, email, password, token) VALUES (:username, :email, :password, :token)";
            
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $statement = (new self)->connection->prepare($sql);
                $statement->bindValue(':username', $username);
                $statement->bindValue(':email', $email);
                $statement->bindValue(':password', $hashed_password);
                $statement->bindValue(':token', "");
                $statement->setFetchMode(PDO::FETCH_OBJ);
                $statement->execute();
    
                echo "Usuario registrado exitosamente";
                return;
    
              } catch(PDOException $error) {
                  echo $sql . "<br>" . $error->getMessage();
                  return null;
              }
        }

    }

    public static function userLogin($username, $password){

        if (!(new self)->exist($username)) {
            //echo "Username does not exists";
            return false;
        } else {
            try {
       
                $sql = "SELECT id, password FROM User WHERE username = :username";

                $statement = (new self)->connection->prepare($sql);
                $statement->bindValue(':username', $username);
                $statement->setFetchMode(PDO::FETCH_OBJ);
                $statement->execute();
    
                $user = $statement->fetch();
    
                if ($user && password_verify($password, $user->password)) {
                    // La autenticación es correcta
                    session_start();
                    
                    $_SESSION['user_id'] = $user->id;
                    $_SESSION['username'] = $username;
                    // Redirigir al usuario a su perfil o a la página de inicio
                    // header("Location: perfil.php");

                    return self::generateToken($user);

                } else {
                    // Usuario o contraseña incorrectos
                    //echo "Nombre de usuario o contraseña incorrectos.";
                    return false;
                }
        
    
              } catch(PDOException $error) {
                  echo $sql . "<br>" . $error->getMessage();
                  return false;
              }
        }
    }

    private static function generateToken($user) {
           
            if (isset($_SESSION['user_id'])) {
                // Genera un token de sesión para recordar al usuario
                $token = bin2hex(random_bytes(16));
                setcookie("token", $token, time() + (86400 * 30), "/"); // 30 días

                // Guarda el token en la base de datos
                $statement = (new self)->connection->prepare("UPDATE User SET token = :token WHERE id = :id");
                $statement->bindValue(':token', $token);
                $statement->bindValue(':id', $user->id);
                
                $statement->execute();
                return true;
            } else {
                return false;
            }
    }

    public static function exist($username, $email = null) {

        if ($email === null) {

            try  {
       
                $sql = "SELECT * 
                        FROM User
                        WHERE username = :username";
            
                $statement = (new self)->connection->prepare($sql);
                $statement->bindValue(':username', $username);
                $statement->setFetchMode(PDO::FETCH_OBJ);
                $statement->execute();
    
                $result = $statement->fetch();
                return !$result ? false : true;
    
              } catch(PDOException $error) {
                  echo $sql . "<br>" . $error->getMessage();
              }

        } else {

            try  {
       
                $sql = "SELECT * 
                        FROM User
                        WHERE username = :username AND email = :email";
            
                $statement = (new self)->connection->prepare($sql);
                $statement->bindValue(':username', $username);
                $statement->bindValue(':email', $email);
                $statement->setFetchMode(PDO::FETCH_OBJ);
                $statement->execute();
    
                $result = $statement->fetch();
                return !$result ? false : true;
    
              } catch(PDOException $error) {
                  echo $sql . "<br>" . $error->getMessage();
              }
        }



    }

    public static function verifyTokenCookie() {

        session_start();
        if (isset($_COOKIE['token'])) {
            $token = $_COOKIE['token'];
            
            $statement = (new self)->connection->prepare("SELECT id, username FROM User WHERE token = :token");
            $statement->bindValue(":token", $token);
            $statement->setFetchMode(PDO::FETCH_OBJ);
            $statement->execute();
            $user = $statement->fetch();

            if ($user) {
                $_SESSION['user_id'] = $user->id;
                $_SESSION['username'] = $user->username;

                return true;
            } else {
                // Token inválido
                setcookie("token", "", time() - 3600, "/"); // Eliminar cookie
                // header("Location: login.php");
                // exit();
                echo "Token inválido!";
                return false;
            }
        } else {
            return false;
        }

    }


    public static function isLoggedIn() {
        return self::verifyTokenCookie();
    }

}