/**
* Light Auth class
* v0.11
*/

<?php

define('AUTH_REALM', 'localhost');
define('AUTH_MAX_ACT_TIME', 3600 * 2); //2 hours
define('AUTH_LOGIN_URL', 'login.php');


abstract class Auth
{
    public $err = '';

    public function __construct() {
        if (!isset($_SESSION)) {
            //Anti session hijack
            ini_set('session.use_only_cookies', true);
            session_start();
            if (!isset($_SESSION['AUTH'])) {
                $_SESSION['AUTH'] = ['salt' => md5(uniqid(mt_rand(), true))];
            }
        }
    }

    /**
     * @return array
     */
    public function getAuthSession()
    {
        $s = $_SESSION['AUTH'];
        if (!is_array($s)) {
            //BIG TROUBLE!!
            exit(0);
        }

        return $s;
    }

    /**
     * @param $key
     * @param $value
     */
    public function setAuthSession($key, $value) {
        if (!is_array($_SESSION['AUTH'])) {
            //BIG TROUBLE!!
            exit(0);
        }
        $_SESSION['AUTH'][$key] = $value;
    }

    /**
     * @param $userName
     * @param $digestHash  MD5(<salt> + MD5(<userName>:<realm>:<password>))
     * @return bool|int    return authority value when success or false when fail
     */
    public function checkAuth() {
        $auth = $this->getAuthSession();
        if (!isset($auth['authority'])) {
            $this->err = 'Login before';
            return false;
        }

        //check timeout
        $now = time();
        if ($now - $auth['last_act_time'] > AUTH_MAX_ACT_TIME) {
            $this->err = 'Timeout, login again';
            $this->logout();
            return false;
        }

        //Anti multi login
        if ($auth['last_ip'] != $_SERVER['REMOTE_ADDR']) {
            $this->err = 'Multi login, IP='.$auth['last_ip'];
            $this->logout();
            return false;
        }

        $auth['last_act_time'] = $now;
        return $auth['authority'];
    }

    /**
     * @param $userName
     * @param $authHash   MUST be MD5(<userName>:<realm>:<password>)
     * @param $authority  authority value
     * @return            success or fail
     */
    public function register($userName, $authHash, $authority) {
        $result = false;
        try {
            $result = $this->createUserAuthority($userName, $authHash, $authority);
        }
        catch (Exception $e) {
            $this->err = $e->getMessage();
        }

        return $result;
    }

    /**
     * @param $userName
     * @param $digestHash  MD5(<salt> + MD5(<userName>:<realm>:<password>))
     * @return bool        success or fail
     */
    public function login($userName, $digestHash) {
        $auth = $this->getAuthSession();

        $authority = false;
        try {
            $authority = $this->checkUserAuthority($userName, $digestHash);
        }
        catch (Exception $e) {
            $this->err = $e->getMessage();
        }

        if ($authority==false) {
            return false;
        }

        $this->setAuthSession('last_act_time', time());
        $this->setAuthSession('last_ip', $_SERVER['REMOTE_ADDR']);
        $this->setAuthSession('authority', $authority);
        $this->afterLogin();
        return true;
    }

    /**
     * Logout
     */
    public function logout() {
        $this->beforeLogout();
        unset($_SESSION['AUTH']);
        if (isset($_COOKIE[session_name()])) {
            setcookie(session_name(), '', time() - 42000);
        }
        session_destroy();
    }



    abstract protected function checkUserAuthority($userName, $digestHash);
    abstract protected function createUserAuthority($userName, $authHash, $authority);
    protected function afterLogin() {}
    protected function beforeLogout() {}
}
