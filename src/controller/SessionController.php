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
                        (username, email, password) VALUES (:username, :email, :password)";
            
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $statement = (new self)->connection->prepare($sql);
                $statement->bindValue(':username', $username);
                $statement->bindValue(':email', $email);
                $statement->bindValue(':password', $hashed_password);
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
            echo "Username does not exists";
            return;
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
                } else {
                    // Usuario o contraseña incorrectos
                    echo "Nombre de usuario o contraseña incorrectos.";
                }
        
                return;
    
              } catch(PDOException $error) {
                  echo $sql . "<br>" . $error->getMessage();
                  return null;
              }
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


}