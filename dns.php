<?php

require 'auth.php';

$servername = "localhost";
$dbUsername = "username";
$dbPassword = "password";
$dnsdbname = "";

if (!isset($_POST["token"], $_POST["action"])) {
    if (isset($_POST["username"], $_POST["password"])){
        $username = $_POST["username"];
        if (ctype_alnum($username)) {
            $password = $_POST["password"];
            $authResult = auth($username, $password);
            echo $authResult. "\n";
            return;
        }
    }
    header("HTTP/1.1 403 Forbidden");
    echo "Access Denied!\n";
    return;
} else {
    $token = $_POST["token"];
    if (ctype_alnum($token) && strlen($token) <= 64) {
        $action = $_POST["action"];
        if (preg_match('/^[a-z_]+$/', "{$action}")) {
            $authCheckResult = auth_status($token);
            if ($authCheckResult !== FALSE) {
                $username = $authCheckResult;
                parse_data($action);
                return;
            }
            return;
        }
    }
    header("HTTP/1.1 400 Bad Request");
    echo "Invalid Token or Action!\n";
    return;
}

//Parse Data
function parse_data($action){
    $data = $_POST["data"];
    $decodedData = json_decode($data, true);

    $action = $GLOBALS["action"];
    if ($action == "get_domain_list"){
        $resultArray = get_domain_list();
        $resultArray = array('domains' => $resultArray);
        $result = json_encode($resultArray);
        echo $result;
        return;
    } else {
        $domainList = get_domain_list();
        $domainRequested = $decodedData["domain"];
        $domainTable = str_replace(".", "_", $domainRequested);
        if (in_array($domainRequested, $domainList)) {
            if ($action == "get_domain_record") {
                get_domain_record($domainTable, $domainRequested);
            } elseif ($action == "get_domain_id_record") {
                $domainIDRequested = $decodedData["domainID"];
                get_domain_id_record($domainTable, $domainRequested, $domainIDRequested);
            } elseif ($action == 'delete_domain_id_record') {
                $domainIDRequested = $decodedData["domainID"];
                delete_domain_id_record($domainTable, $domainIDRequested);
            } elseif ($action == 'update_ddns') {
                $domainIDRequested = $decodedData["domainID"];
                ddns_update($domainTable, $domainIDRequested);
            } elseif ($action == "update_domain_record") {
                $updateData = $decodedData["records"];
                update_domain_record($domainTable, $domainRequested, $updateData);
            } elseif ($action == "update_domain_id_record") {
                $domainIDRequested = $decodedData["domainID"];
                $updateData = $decodedData["record"]["data"];
                update_domain_id_record($domainTable, $domainRequested, $domainIDRequested, $updateData);
            } else {
                header("HTTP/1.1 400 Bad Request");
                echo "Unknown Action!\n";
            }
        return;
        } else {
            header("HTTP/1.1 403 Forbidden");
            echo "Permission Denied!\n";
            return;
        }
    }
}

//Get Domain List
function get_domain_list(){
    $sql = "SELECT id, username, domains FROM domain_list WHERE username='{$GLOBALS["username"]}'";
    $result = mysql_request($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $resultArray = explode(', ', $row['domains']);
        return $resultArray;
    } else {
        header("HTTP/1.1 404 Not Found");
        echo "No Valid Domain Found!\n";
        return;
    }
}

//DNS Action

//Get Record for Domain
function get_domain_record($domainTable, $domainRequested){
    $sql = "SELECT id, type, host, data, ttl, resp_person, serial, refresh, retry, expire, minimum_ttl FROM $domainTable  WHERE zone='{$domainRequested}'";
    $result = mysql_request($sql);

    if ($result->num_rows > 0) {
        $resultArray = array();
        while ($row = $result->fetch_assoc()) {
            if ($row['type'] != 'SOA'){
                $resultArray[] = array('domainID'=>$row['id'], 'data'=>array('type'=>$row['type'], 'host'=>$row['host'], 'data'=>$row['data'], 'ttl'=>$row['ttl']));
            } else {
                $resultArray[] = array('domainID'=>$row['id'], 'data'=>array('type'=>$row['type'], 'host'=>$row['host'], 'ttl'=>$row['ttl'],
                 'primaryNS'=>$row['data'], 'responsePerson'=>$row['resp_person'], 'serialID'=>$row['serial'], 'refreshTime'=>$row['refresh'],
                 'retryTime'=>$row['retry'], 'expireTime'=>$row['expire'], 'minimumTtl'=>$row['minimum_ttl']));
            }
        }
        $resultArray = array('domain' => $domainRequested, 'records'=>$resultArray);
        $result = json_encode($resultArray);
        echo $result;
        return;
    }
    header("HTTP/1.1 400 Bad Request");
    echo "Action Failed!\n";
    return;
}

//Get Specified Record with Domain and Domain ID
function get_domain_id_record($domainTable, $domainRequested, $domainIDRequested){
    $sql = "SELECT id, type, host, data, ttl, resp_person, serial, refresh, retry, expire, minimum_ttl FROM $domainTable WHERE id='{$domainIDRequested}'";
    $result = mysql_request($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if ($row['type'] == 'SOA') {
            $resultArray[] = array('domainID'=>$row['id'], 'data'=>array('type'=>$row['type'], 'host'=>$row['host'], 'ttl'=>$row['ttl'],
             'primaryNS'=>$row['data'], 'responsePerson'=>$row['resp_person'], 'serialID'=>$row['serial'], 'refreshTime'=>$row['refresh'],
             'retryTime'=>$row['retry'], 'expireTime'=>$row['expire'], 'minimumTtl'=>$row['minimum_ttl']));
        } else {
            $resultArray[] = array('domainID'=>$row['id'], 'data'=>array('type'=>$row['type'], 'host'=>$row['host'], 'data'=>$row['data'], 'ttl'=>$row['ttl']));
        }
        $resultArray = array('domain' => $domainRequested, 'records'=>$resultArray);
        $result = json_encode($resultArray);
        echo $result;
        return;
    }
    header("HTTP/1.1 400 Bad Request");
    echo "Action Failed!\n";
    return;
}

//Delete Specified Record with Domain and Domain ID
function delete_domain_id_record($domainTable, $domainIDRequested) {
    $sql = "DELETE FROM $domainTable WHERE id='{$domainIDRequested}'";
    $result = mysql_request($sql);

    if ($result == TRUE) {
        echo "Record of ID ". $domainIDRequested. " deleted successfully!\n";
        return;
    }
    header("HTTP/1.1 400 Bad Request");
    echo "Action Failed!\n";
}

//Update DDNS IP
function ddns_update($domainTable, $domainIDRequested) {
    $ip = get_ip();
    $sql = "UPDATE $domainTable SET data='{$ip}' WHERE id='{$domainIDRequested}'";

    $result = mysql_request($sql);
        if ($result == TRUE) {
            echo "Record Updated Successfully for Domain ID ". $domainIDRequested. "\n";
            return;
        } else {
            echo "Failed to Update Record!\n";
        }
}

//Update All Record for Domain with Data
function update_domain_record($domainTable, $domainRequested, $updateData){
    foreach ($updateData as $id => $updateData) {
        $domainID = $updateData["domainID"];
        $domainData = $updateData["data"];
        update_domain_id_record($domainTable, $domainRequested, $domainID, $domainData);
    }
    return;
}

//Update Specified Record with Domain, Domain ID and Data
function update_domain_id_record($domainTable, $domainRequested, $domainIDRequested, $updateData) {
    $sql = "SELECT id, host FROM $domainTable WHERE id='{$domainIDRequested}'";
    $result = mysql_request($sql);

    $newType = $updateData["type"];
    $newType = strtoupper($newType);
    $newHostname = $updateData["host"];
    $newData = $updateData["data"];
    if (!isset($newData)) {
        $newData = $updateData["primaryNS"];
    }
    $newTtl = $updateData["ttl"];
    if (!isset($newTtl)) {
        $newTtl = '600';
    }
    $newHostname = parse_hostname($newHostname, $domainRequested);
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (value_check($domainIDRequested, $newType, $newData) == TRUE) {
            if ($newType == 'SOA') {
                $newResponsePerson = $updateData["responsePerson"];
                $newSerial = $updateData["serialID"];
                $newRefresh = $updateData["refreshTime"];
                $newRetry = $updateData["retryTime"];
                $newExpire = $updateData["expireTime"];
                $newMinimumTtl = $updateData["minimumTtl"];
                $sql = "UPDATE $domainTable SET type='{$newType}', host='{$newHostname}', data='{$newData}', resp_person='{$newResponsePerson}',
                serial='{$newSerial}', refresh='{$newRefresh}', retry='{$newRetry}', expire='{$newExpire}',minimum_ttl='{$newMinimumTtl}',
                 ttl='{$newTtl}' WHERE id='{$domainIDRequested}'";
            } else {
                $sql = "UPDATE $domainTable SET type='{$newType}', host='{$newHostname}', data='{$newData}', ttl='{$newTtl}' WHERE id='{$domainIDRequested}'";
            }
            $result = mysql_request($sql);
            if ($result == TRUE) {
                echo "Record Updated Successfully for Domain ID ". $domainIDRequested. "\n";
                return;
            }
        }
    } elseif (value_check($domainIDRequested, $newType, $newData) == TRUE) {
        $sql = "INSERT INTO $domainTable VALUE ('{$domainIDRequested}', '{$domainRequested}', '{$newType}', '{$newHostname}', '{$newData}',
         '{$newTtl}', NULL, NULL, NULL, NULL, NULL, NULL)";
        $result = mysql_request($sql);
        if ($result == TRUE) {
            echo "Record Inserted Successfully for Domain ID ". $domainIDRequested. "\n";
            return;
        } else {
            header("HTTP/1.1 400 Bad Request");
            echo "Invalid Parameter!\n";
        }
    }
    header("HTTP/1.1 400 Bad Request");
    echo "Action Failed!\n";
    return;
}

//Parse Hostname
function parse_hostname($hostname, $domainRequested){
    $regexParameter = '/(.*?(\b' . $domainRequested . '[.]' . '\B)[^$]*)$/';
    if (preg_match($regexParameter, $hostname) == FALSE) {
        $hostname = $hostname;
    } else {
        $hostname = preg_replace($regexParameter, $hostname, '@');
    }
    return $hostname;
}

//Check Value
function value_check($domainID, $type, $data){
    if ($domainID == '1' && $type != 'SOA') {
        header("HTTP/1.1 400 Bad Request");
        echo "First record must be SOA record!\n";
        return FALSE;
    }
    if ($type == 'A') {
        if (preg_match('/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/', "{$data}") == TRUE) {
            return TRUE;
        }
        return FALSE;
    }
    if ($type == 'AAAA') {
        if (preg_match('/(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))/', "{$data}") == TRUE) {
            return TRUE;
        }
        return FALSE;
    }
    if ($type == 'CNAME' or $type == 'NS') {
        if (preg_match('/^([a-z0-9_]+(-[a-z0-9]+)*.)+[a-z]{0,}$/', "{$data}") == TRUE) {
            return TRUE;
        }
        return FALSE;
    }
    if (preg_match('/^[A-Z]{1,10}$/', "{$type}") == TRUE) {
        return TRUE;
    }
    return FALSE;
}

function get_ip() {
    $ip = isset($_GET['ip']) && $_GET['ip'] ? $_GET['ip'] : '';
    if (!$ip) {
	    if (isset($_SERVER['HTTP_INCAP_CLIENT_IP'])) {
	    	$ip = $_SERVER['HTTP_INCAP_CLIENT_IP'];
	    } else if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
	    	$ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
	    } else {
	    	$ip = $_SERVER['REMOTE_ADDR'];
	    }
    }

    return $ip;
}

//Send MySQL Request
function mysql_request($sql){
    $conn = new mysqli($GLOBALS["servername"], $GLOBALS["dbUsername"], $GLOBALS["dbPassword"], $GLOBALS["dnsdbname"]);
    $result = $conn->query($sql);

    $conn->close();
    return $result;
}
?>