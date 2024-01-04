<?php

/**
 * Tiny Tiny RSS plugin for LDAP authentication
 * @author tsmgeek (tsmgeek@gmail.com)
 * @author hydrian (ben.tyger@tygerclan.net)
 * @author pasbec (p.b-dev+ttrss@mailbox.org)
 *  Requires php-ldap 
 * @version 3.0
 */

class Auth_Ldap extends Auth_Base {

    const REPLACE = "login=%login&password=%password";

    const LDAP_URI = "LDAP_URI";
    const LDAP_TLS = "LDAP_TLS";
    const LDAP_BIND_DN = "LDAP_BIND_DN";
    const LDAP_BIND_PW = "LDAP_BIND_PW";
    const LDAP_BASE_DN = "LDAP_BASE_DN";
    const LDAP_ADMIN_FILTER = "LDAP_ADMIN_FILTER";
    const LDAP_USER_FILTER = "LDAP_USER_FILTER";
    const LDAP_USER_ATTRIBUTE = "LDAP_USER_ATTRIBUTE";
    const LDAP_NAME_ATTRIBUTE = "LDAP_NAME_ATTRIBUTE";
    const LDAP_MAIL_ATTRIBUTE = "LDAP_MAIL_ATTRIBUTE";
    const LDAP_REPLACE = "LDAP_REPLACE";
    const LDAP_REPLACE_BIND = "LDAP_REPLACE_BIND";

    private function log($msg, $level = E_USER_NOTICE, $file = "", $line = 0, $context = "") {
        Logger::log_error($level, "auth_ldap: $msg", $file, $line, $context);
    }

    function about() {
        return array(
            3.0,
            "Authenticates against some LDAP server",
            "pasbec",
            true,
            "https://github.com/pasbec/ttrss-auth-ldap"
        );
    }

    function init($host) {

        Config::add(self::LDAP_URI, "", Config::T_STRING);
        Config::add(self::LDAP_TLS, "true", Config::T_BOOL);
        Config::add(self::LDAP_BIND_DN, "", Config::T_STRING);
        Config::add(self::LDAP_BIND_PW, "", Config::T_STRING);
        Config::add(self::LDAP_BASE_DN, "", Config::T_STRING);
        Config::add(self::LDAP_ADMIN_FILTER, "", Config::T_STRING);
        Config::add(self::LDAP_USER_FILTER, "", Config::T_STRING);
        Config::add(self::LDAP_USER_ATTRIBUTE, "", Config::T_STRING);
        Config::add(self::LDAP_NAME_ATTRIBUTE, "", Config::T_STRING);
        Config::add(self::LDAP_MAIL_ATTRIBUTE, "", Config::T_STRING);
        Config::add(self::LDAP_REPLACE, self::REPLACE, Config::T_STRING);
        Config::add(self::LDAP_REPLACE_BIND, "true", Config::T_BOOL);

        $host->add_hook($host::HOOK_AUTH_USER, $this);
    }

    function authenticate($login, #[\SensitiveParameter] $password, $service = "") {

        if ($login && $password) {

            if (!function_exists("ldap_connect")) {
                trigger_error("auth_ldap requires LDAP support");
                return false;
            }

            // Get configuration settings
            $uri = Config::get(self::LDAP_URI);
            $tls = Config::get(self::LDAP_TLS);
            $bind_dn = Config::get(self::LDAP_BIND_DN);
            $bind_pw = Config::get(self::LDAP_BIND_PW);
            $base_dn = Config::get(self::LDAP_BASE_DN);
            $admin_filter = Config::get(self::LDAP_ADMIN_FILTER);
            $user_filter = Config::get(self::LDAP_USER_FILTER);
            $user_attribute = Config::get(self::LDAP_USER_ATTRIBUTE);
            $name_attribute = Config::get(self::LDAP_NAME_ATTRIBUTE);
            $mail_attribute = Config::get(self::LDAP_MAIL_ATTRIBUTE);
            $replace = Config::get(self::LDAP_REPLACE);
            $replace_bind = Config::get(self::LDAP_REPLACE_BIND);

            // Check URI
            $parsed_uri = parse_url($uri);
            if ($parsed_uri == false) {
                $this->log("Server URI is required and not defined", E_USER_ERROR);
                return false;
            }

            // Check base DN
            if (empty($base_dn)) {
                $this->log("Base DN is required and not defined", E_USER_ERROR);
                return false;
            }

            // Create LDAP connection
            $ldap = @ldap_connect($uri);
            if ($ldap == false) {
                $this->log("Could not connect to server URI '$uri'", E_USER_ERROR);
                return false;
            }

            // Adjust protocol version
            if (!@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
                $this->log("Failed to set LDAP Protocol version to 3", E_USER_ERROR);
                return false;
            }

            // Adjust referrals
            if (!@ldap_set_option($ldap, LDAP_OPT_REFERRALS, false)) {
                $this->log("Failed to set LDAP referrals to false", E_USER_ERROR);
                return false;
            }

            // Enable TLS if enabled
            if ($tls) {
                if (!@ldap_start_tls($ldap)) {
                    $this->log("Failed to enable TLS for URI '$uri'", E_USER_ERROR);
                    return false;
                }
            }

            // Parse replacement map
            $_replace = [];
            try {
                parse_str($replace, $_replace);
            } catch (Exception) {
                $this->log("Failed to parse replacement map '$replace'", E_USER_WARNING);
            }
            parse_str(self::REPLACE, $_replace_default);
            foreach ($_replace_default as $key => $value) {
                if (!array_key_exists($key, $_replace)) {
                    $this->log(
                        "Missing key '$key' in replacement map '$replace'.".
                        " Falling back to default map '".self::REPLACE."'",
                        E_USER_WARNING
                    );
                    $_replace = $_replace_default;
                    break;
                }
            }

            // Create escaped bind credentials
            $_bind_dn = $bind_dn;
            $_bind_pw = $bind_pw;
            if ($replace_bind) {
                $_bind_dn = strtr($_bind_dn, [$_replace["login"] => ldap_escape($login, "", LDAP_ESCAPE_DN)]);
                $_bind_pw = strtr($_bind_pw, [$_replace["password"] => $password]);
            }

            // Bind
            if (@ldap_bind($ldap, $_bind_dn, $_bind_pw)) {
                $this->log("Bind successful for '$_bind_dn'");
            } else {
                $this->log("Bind failed for '$_bind_dn'");
                return false;
            }

            // Create escaped search filter strings
            $_admin_filter = strtr($admin_filter, [$_replace["login"] => ldap_escape($login, "", LDAP_ESCAPE_FILTER)]);
            $_user_filter = strtr($user_filter, [$_replace["login"] => ldap_escape($login, "", LDAP_ESCAPE_FILTER)]);
            $filter_info = "admin-filter '$_admin_filter' and user-filter '$_user_filter'";

            // Create search attribute array
            $attributes = array("cn");
            if (!empty($user_attribute)) array_push($attributes, $user_attribute);
            if (!empty($name_attribute)) array_push($attributes, $name_attribute);
            if (!empty($mail_attribute)) array_push($attributes, $mail_attribute);
            $attributes = array_unique($attributes);

            // Search
            $admin_search = empty($admin_filter) ? null : @ldap_search($ldap, $base_dn, $_admin_filter, $attributes);
            $user_search = empty($user_filter) ? null : @ldap_search($ldap, $base_dn, $_user_filter, $attributes);
            if (($admin_search == false) && ($user_search == false)) {
                $this->log("Search failed with $filter_info", E_USER_ERROR);
                return false;
            }

            // Check search result count
            $admin_count = is_null($admin_search) ? 0 : @ldap_count_entries($ldap, $admin_search);
            $user_count = is_null($user_search) ? 0 : @ldap_count_entries($ldap, $user_search);
            if ($admin_count > 1 || $user_count > 1) {
                $this->log("Ambiguous login with $filter_info", E_USER_WARNING);
                return false;
            } elseif ($admin_count == 0 && $user_count == 0) {
                $this->log("Invalid login with $filter_info");
                return false;
            }

            // Get user entry
            $admin_entry = !$admin_count ? null : @ldap_first_entry($ldap, $admin_search);
            $user_entry = !$user_count ? null : @ldap_first_entry($ldap, $user_search);
            if ($admin_entry === false || $user_entry === false) {
                $this->log("Unable to get user entry with $filter_info", E_USER_ERROR);
                return false;
            }
            
            // Get user DN
            $admin_dn = is_null($admin_entry) ? null : @ldap_get_dn($ldap, $admin_entry);
            $user_dn = is_null($user_entry) ? null : @ldap_get_dn($ldap, $user_entry);
            if ($admin_dn === false || $user_dn === false) {
                $this->log("Unable to get user DN with $filter_info", E_USER_ERROR);
                return false;
            }

            // Get user attributes
            $admin_attributes = is_null($admin_entry) ? null : @ldap_get_attributes($ldap, $admin_entry);
            $user_attributes = is_null($user_entry) ? null : @ldap_get_attributes($ldap, $user_entry);

            // Admin consistency check
            if ($admin_count) {
                if ($user_count && ($admin_dn != $user_dn)) {
                    $this->log("Inconsistent login with $filter_info", E_USER_WARNING);
                    return false;
                }
                $user_dn = $admin_dn;
                $user_attributes = $admin_attributes;
            }

            // Bind with user DN
            $bind = @ldap_bind($ldap, $user_dn, $password);
            @ldap_close($ldap);
            if ($bind == true) {
                $this->log("Authentication successful for user DN '$user_dn'");

                // Get user name
                if (strlen($user_attribute) > 0) {
                    $username = $user_attributes[$user_attribute][0];
                    if (!is_string($username)) {
                        $this->log("Unable to get user attribute '$user_attribute' for user DN '$user_dn'", E_USER_ERROR);
                        return false;
                    }
                } else {
                    $username = $login;
                }

                // Get/create user ID and create user instance
                $user_id = $this->auto_create_user($username);
                $user = ORM::for_table("ttrss_users")->find_one($user_id);

                // Update name
                if (strlen($name_attribute) > 0) {
                    $name = $user_attributes[$name_attribute][0];
                    if (is_string($name)) {
                        $user->full_name = $name;
                    } else {
                        $this->log("Unable to get name attribute '$name_attribute' for user DN '$user_dn'", E_USER_WARNING);
                    } 
                }

                // Update email
                if (strlen($mail_attribute) > 0) {
                    $mail = $user_attributes[$mail_attribute][0];
                    if (is_string($mail)) {
                        $user->email = $mail;
                    } else {
                        $this->log("Unable to get mail attribute '$mail_attribute' for user DN '$user_dn'", E_USER_WARNING);
                    } 
                }

                // Update access level
                if ($admin_count) {
                    $user->access_level = UserHelper::ACCESS_LEVEL_ADMIN;
                } else {
                    $user->access_level = UserHelper::ACCESS_LEVEL_USER;
                }

                // Save user data
                $user->save();

                // Return user ID
                return $user_id;
            } else {
                $this->log("Authentication failed for user DN '$user_dn'", E_USER_ERROR);
                return false;
            }
        }

        return false;
    }

    function api_version() {
        return 2;
    }
}

?>
