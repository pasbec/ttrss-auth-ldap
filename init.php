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

    const LDAP_URI = "LDAP_URI";
    const LDAP_USE_TLS = "LDAP_USE_TLS";
    const LDAP_BIND_DN = "LDAP_BIND_DN";
    const LDAP_BIND_PW = "LDAP_BIND_PW";
    const LDAP_BASE_DN = "LDAP_BASE_DN";
    const LDAP_SEARCH_FILTER = "LDAP_SEARCH_FILTER";
    const LDAP_USER_ATTRIBUTE = "LDAP_USER_ATTRIBUTE";
    const LDAP_NAME_ATTRIBUTE = "LDAP_NAME_ATTRIBUTE";
    const LDAP_MAIL_ATTRIBUTE = "LDAP_MAIL_ATTRIBUTE";

    private function log($msg, $level = E_USER_NOTICE, $file = '', $line = 0, $context = '') {
        Logger::log_error($level, "auth_ldap: " . $msg, $file, $line, $context);
    }

    function about() {
        return array(
            3.0,
            "Authenticates against some LDAP server",
            "pasbec",
            TRUE,
            "https://github.com/pasbec/ttrss-auth-ldap"
        );
    }

    function init($host) {

        Config::add(self::LDAP_URI, "", Config::T_STRING);
        Config::add(self::LDAP_USE_TLS, "true", Config::T_BOOL);
        Config::add(self::LDAP_BIND_DN, "", Config::T_STRING);
        Config::add(self::LDAP_BIND_PW, "", Config::T_STRING);
        Config::add(self::LDAP_BASE_DN, "", Config::T_STRING);
        Config::add(self::LDAP_SEARCH_FILTER, "", Config::T_STRING);
        Config::add(self::LDAP_USER_ATTRIBUTE, "", Config::T_STRING);
        Config::add(self::LDAP_NAME_ATTRIBUTE, "", Config::T_STRING);
        Config::add(self::LDAP_MAIL_ATTRIBUTE, "", Config::T_STRING);

        $host->add_hook($host::HOOK_AUTH_USER, $this);
    }

    function authenticate($login, $password, $service = "") {

        if ($login && $password) {

            if (!function_exists('ldap_connect')) {
                trigger_error('auth_ldap requires LDAP support');
                return FALSE;
            }

            // Get configuration settings
            $uri = Config::get(self::LDAP_URI);
            $use_tls = Config::get(self::LDAP_USE_TLS);
            $bind_dn = Config::get(self::LDAP_BIND_DN);
            $bind_pw = Config::get(self::LDAP_BIND_PW);
            $base_dn = Config::get(self::LDAP_BASE_DN);
            $search_filter = Config::get(self::LDAP_SEARCH_FILTER);
            $user_attribute = Config::get(self::LDAP_USER_ATTRIBUTE);
            $name_attribute = Config::get(self::LDAP_NAME_ATTRIBUTE);
            $mail_attribute = Config::get(self::LDAP_MAIL_ATTRIBUTE);

            // Check URI
            $parsed_uri = parse_url($uri);
            if ($parsed_uri == FALSE) {
                $this->log('Server URI is required and not defined', E_USER_ERROR);
                return FALSE;
            }
            // $scheme = $parsed_uri['scheme'];

            // Check base DN
            if (empty($base_dn)) {
                $this->log('Base DN is required and not defined', E_USER_ERROR);
                return FALSE;
            }

            // Create LDAP connection
            $ldap = @ldap_connect($uri);
            if ($ldap == FALSE) {
                $this->log('Could not connect to server URI \'' . $uri . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Set protocol version 
            if (!@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
                $this->log('Failed to set LDAP Protocol version (LDAP_OPT_PROTOCOL_VERSION) to 3', E_USER_ERROR);
                return FALSE;
            }

            // Set referrals
            if (!@ldap_set_option($ldap, LDAP_OPT_REFERRALS, FALSE)) {
                $this->log('Failed to set LDAP referrals (LDAP_OPT_REFERRALS) to FALSE', E_USER_ERROR);
                return FALSE;
            }

            // Enable TLS if enabled
            if ($use_tls) {
                if (!@ldap_start_tls($ldap)) {
                    $this->log('Failed to enable TLS for URI \'' . $uri . '\'', E_USER_ERROR);
                    return FALSE;
                }
            }

            // Process bind input
            $_bind_dn = NULL;
            $_bind_pw = NULL;
            if (!empty($bind_dn)) {
                $_bind_dn = strtr($bind_dn, ['{login}' => $login]);
            }
            if (!empty($bind_pw)) {
                $_bind_pw = strtr($bind_pw, ['{password}' => $password]);
            }

            // Bind 
            $bind = @ldap_bind($ldap, $_bind_dn, $_bind_pw);
            if ($bind == TRUE) {
                $this->log('Bind successful for \'' . $_bind_dn . '\'');
            } else {
                $this->log('Bind failed for \'' . $_bind_dn . '\'');
                return FALSE;
            }

            // Create search filter string
            $filter = strtr($search_filter, ['{login}' => ldap_escape($login)]);

            // Create search attribute array
            $attributes = array('cn');
            if (!empty($user_attribute)) {
                array_push($attributes, $user_attribute);
            }
            if (!empty($name_attribute)) {
                array_push($attributes, $name_attribute);
            }
            if (!empty($mail_attribute)) {
                array_push($attributes, $mail_attribute);
            }
            $attributes = array_unique($attributes);

            // Search
            $searchResults = @ldap_search($ldap, $base_dn, $filter, $attributes, 0, 0, LDAP_DEREF_NEVER);
            if ($searchResults == FALSE) {
                $this->log('Search failed for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Check search result count
            $count = @ldap_count_entries($ldap, $searchResults);
            if ($count > 1) {
                $this->log('Multiple DNs found for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            } elseif ($count == 0) {
                $this->log('Unknown login \'' . $login . '\'');
                return FALSE;
            }

            // Get user entry
            $user_entry = @ldap_first_entry($ldap, $searchResults);
            if ($user_entry == FALSE) {
                $this->log('Unable to get user entry for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Get user attributes
            $user_attributes = @ldap_get_attributes($ldap, $user_entry);
            if ($user_entry == FALSE) {
                $this->log('Unable to get user attributes for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }
            
            // Get user DN
            $user_dn = @ldap_get_dn($ldap, $user_entry);
            if ($user_dn == FALSE) {
                $this->log('Unable to get user DN for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Bind with user DN
            $bind = @ldap_bind($ldap, $user_dn, $password);
            @ldap_close($ldap);
            if ($bind == TRUE) {
                $this->log('Authentication successful for user DN \'' . $user_dn . '\'');

                // Get user name
                if (strlen($user_attribute) > 0) {
                    $username = $user_attributes[$user_attribute][0];
                    if (!is_string($username)) {
                        $this->log('Unable to get user attribute \'' . $user_attribute . '\' for user DN \'' . $user_dn . '\'', E_USER_ERROR);
                        return FALSE;
                    }
                } else {
                    $username = $login;
                }

                // Get/create user ID and create user instance
                $user_id = $this->auto_create_user($username);
                $user = ORM::for_table('ttrss_users')->find_one($user_id);

                // Update full user name
                if (strlen($name_attribute) > 0) {
                    $name = $user_attributes[$name_attribute][0];
                    if (is_string($name)) {
                        $user->full_name = $name;
                    } else {
                        $this->log('Unable to get name attribute \'' . $name_attribute . '\' for user DN \'' . $user_dn . '\'', E_USER_WARNING);
                    } 
                }

                // Update user email
                if (strlen($mail_attribute) > 0) {
                    $mail = $user_attributes[$mail_attribute][0];
                    if (is_string($mail)) {
                        $user->email = $mail;
                    } else {
                        $this->log('Unable to get mail attribute \'' . $mail_attribute . '\' for user DN \'' . $user_dn . '\'', E_USER_WARNING);
                    } 
                }

                // Save user data
                $user->save();

                // Return user ID
                return $user_id;
            } else {
                $this->log('Authentication failed for user DN \'' . $user_dn . '\'', E_USER_ERROR);
                return FALSE;
            }
        }

        return FALSE;
    }

    function api_version() {
        return 2;
    }
}

?>
