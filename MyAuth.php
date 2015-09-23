<?php

include_once __DIR__ . '/Auth.class.php';


class MyAuth extends Auth {
    protected function checkUserAuthority($userName, $digestHash) {
        $auth = $this->getAuthSession();
        $sampleDigestHash = md5($auth['salt'].md5('admin:'.AUTH_REALM.':'.'admin'));
        if ($userName=='admin' && $digestHash==$sampleDigestHash) {
            return 999; //authority
        }

        return false;
    }

    protected function createUserAuthority($userName, $authHash, $authority) {
        $sampleAuthHash = md5('admin:'.AUTH_REALM.':'.'admin');
        if ($userName=='admin' && $authHash==$sampleAuthHash && $authority==999) {
            return true;
        }

        return true;
    }

    protected function afterLogin() {
        $this->setAuthSession('user_id', 100);
    }

}
