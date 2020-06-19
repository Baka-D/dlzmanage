<?php

$authdbname = "";

//Auth Action
//Auth
function auth($username, $password){
    if (check_username_password($username, $password) == TRUE) {
        $sql = "SELECT id, username, password FROM Users WHERE username='{$username}'";
        $result = auth_mysql_request($sql);

        $row = $result->fetch_assoc();
        $userid = $row["id"];
        if (check_ua() === FALSE){
            if (check_api_token($userid) !== TRUE){
                $apiToken = check_api_token($userid);
                return $apiToken;
            }
        }
        $token = generate_token();
        insert_token($token, $userid);
        return $token;
    } else {
        header("HTTP/1.1 403 Forbidden");
        $result = "Invalid Username or Password!";
        return $result;
    }
}

//Check Username and Password
function check_username_password($username, $password) {
    $sql = "SELECT username, password FROM Users WHERE username='{$username}'";
    $result = auth_mysql_request($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $passwordFromDB = $row["password"];
        if (password_verify($password, $passwordFromDB)) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
}

//Check UA
function check_ua(){
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    if (strpos($userAgent, 'curl') === FALSE){
        return TRUE; //User Agent != curl
    } else {
        return FALSE;//User Agent == curl
    }
}

//Check API Token
function check_api_token($userid){
    $sql = "SELECT userid, apiToken FROM Users WHERE id='{$userid}'";
    $result = auth_mysql_request($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $apiToken = $row["apiToken"];
        if (is_null($apiToken) !== TRUE){ //if apiToken isnt null then
            return $apiToken;
        }
    }
    return TRUE;
}

//Generate Token
function generate_token(){
    if (check_ua() == TRUE){
        $binToken = openssl_random_pseudo_bytes(16);
    } else {
        $binToken = openssl_random_pseudo_bytes(32); //if from curl then generate 64 bit token
    }
    $token = bin2hex($binToken);

    return $token;
}


//Insert Token
function insert_token($token, $userid){
    $time = time();
    if (check_ua() == TRUE){
        $sql = "UPDATE Users SET token='{$token}', time=$time WHERE id='{$userid}'";
    } else {
        $sql = "UPDATE Users SET apiToken='{$token}' WHERE id='{$userid}'";
    }
    auth_mysql_request($sql);

    return;
}

//Auth Status
function auth_status($token){
    if (check_ua() === TRUE) {
        $sql = "SELECT id, username, token, time FROM Users WHERE token='{$token}'";
        $result = auth_mysql_request($sql);

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $username = $row["username"];
            $timeFromDB = $row["time"];
            $expireTime = $timeFromDB + 86400;
            $currentTime = time();
            if ($currentTime < $expireTime) {
                return $username;
            }
        }
    } else {
        $sql = "SELECT id, username, apiToken FROM Users WHERE apiToken='{$token}'";
        $result = auth_mysql_request($sql);

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $username = $row["username"];
            return $username;
        }
    }
    header("HTTP/1.1 403 Forbidden");
    echo "Invalid Token or Token Expired!";
    return FALSE;
}

//Send MySQL Request
function auth_mysql_request($sql){
    $conn = new mysqli($GLOBALS["servername"], $GLOBALS["dbUsername"], $GLOBALS["dbPassword"], $GLOBALS["authdbname"]);
    $result = $conn->query($sql);

    $conn->close();
    return $result;
}
?>