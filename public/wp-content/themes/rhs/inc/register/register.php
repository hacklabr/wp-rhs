<?php
require_once __DIR__ . "./../traits/emailValidator.php";

class RHSRegister extends RHSMessage {
    use emailValidator;

    function __construct() {
        add_action('wp_ajax_nopriv_check_email_exist', array( &$this, 'check_email_exist'));
        add_filter( "register_url", array( &$this, "register_url" ) );
    }

    public function trigger_by_post() {
        $_isPOST = $_SERVER['REQUEST_METHOD'] === 'POST';
        $_isRegister = !empty($_POST['register_user_wp']) && $_POST['register_user_wp'] == $this->getKey();

        if ($_isPOST && $_isRegister) {

            error_log("BEFORE is_email_blacklisted");


            if ($this->is_email_blacklisted($_POST['mail'])) {
                return;
            }

            error_log("BEFORE validate_by_post");


            if (!$this->validate_by_post()) {
                return;
            }
            error_log("BEFORE HONEYPOT");

            // HoneyPot fields
            if ((isset($_POST['mail']) && empty($_POST['mail'])) ||
                (isset($_POST['pass']) && empty($_POST['pass']))) {

                return;
            }

            error_log("BEFORE insert");

            $this->insert(
                $_POST['mail'],
                $_POST['first_name'],
                $_POST['last_name'],
                $_POST['pass'],
                $_POST['description'],
                $_POST['estado'],
                $_POST['municipio']
            );
        }
    }

    function insert( $mail, $first_name, $last_name, $pass, $description, $state, $city ) {
        error_log("insert");

        $userdata = array(
            'user_login'  => wp_strip_all_tags( trim( $mail ) ),
            'user_email'  => wp_strip_all_tags( trim( $mail ) ),
            'first_name'  => wp_strip_all_tags( trim( $first_name ) ),
            'last_name'   => wp_strip_all_tags( trim( $last_name ) ),
            'user_url'    => '',
            'user_pass'   => $pass,
            'description' => $description,
            'user_nicename' => sanitize_title($first_name.' '.$last_name),
            'role' => 'contributor'
        );

        $user_id = wp_insert_user( $userdata );

        if(is_wp_error( $user_id )) {
            error_log("ERRO WORPDRESS");
            error_log(json_encode($user_id));
        }
        
        rhs_new_user_notification($user_id, $pass);
        
        do_action('rhs_register', $user_id);

        add_user_ufmun_meta( $user_id, $city, $state );

        $perfil = new RHSPerfil( $user_id );
        $perfil->clear_messages();
        $perfil->set_messages( '<i class="fa fa-check"></i> Cadastro realizado', false, 'success' );

        $user_login    = esc_attr( $mail );
        $user_password = esc_attr( $pass );

        $creds                  = array();
        $creds['user_login']    = $user_login;
        $creds['user_password'] = $user_password;
        $creds['remember']      = true;

        $user = wp_signon( $creds, false );

        if ( !is_wp_error( $user ) ) {

            wp_set_current_user( $user_id, $user_login );
            wp_set_auth_cookie( $user_id, true, false );
            do_action( 'wp_login', $user_login,  $user);

        } else {

            $login = new RHSLogin();
            $login->clear_messages();

            foreach ( $user->get_error_message() as $error ) {
                $login->set_messages( $error, false, 'success' );
            }
            wp_redirect( home_url(RHSRewriteRules::LOGIN_URL) );

            return;
        }

        wp_redirect( esc_url(home_url()) );
        exit;

    }

    private function emails_are_equal($mail1, $mail2) {
        return $mail1 === $mail2;
    }

    private function set_error($error_str) {
        $msg = '<i class="fa fa-exclamation-triangle "></i> ' . $error_str;
        $this->set_messages($msg, false, 'error');
    }

    function validate_by_post() {

        $this->clear_messages();

        if ( email_exists( $_POST['mail'] ) ) {
            $this->set_error('Email já está em uso!');

            return false;
        }

        if ( ! array_key_exists( 'mail', $_POST ) ) {
            $this->set_error('Preencha o seu email!');

            return false;
        }

        if( ! $this->emails_are_equal($_POST['mail'], $_POST['mail_confirm']) ) {
            $this->set_error('Os e-mails não conferem!');

            return false;
        }

        if ( ! array_key_exists( 'first_name', $_POST ) ) {
            $this->set_error('Preencha o seu primeiro nome!');

            return false;
        }

        if ( ! array_key_exists( 'last_name', $_POST ) ) {
            $this->set_error('Preencha o seu último nome!');

            return false;
        }

        if ( ! array_key_exists( 'pass', $_POST ) ) {
            $this->set_error('Preencha a sua senha!');

            return false;
        }

        if ( ! array_key_exists( 'description', $_POST ) ) {
            $_POST['description'] = '';

            return false;
        }

        if ( ! array_key_exists( 'estado', $_POST ) ) {
            $_POST['estado'] = '';

            return false;
        }

        if ( ! array_key_exists( 'municipio', $_POST ) ) {
            $_POST['municipio'] = '';

            return false;
        }

        return true;
    }

    static function register_url( $url ) {
        return home_url( RHSRewriteRules::REGISTER_URL );
    }

    public function check_email_exist() {

        $email = $_POST['email'];

        if ( username_exists( $email ) ) {
            echo json_encode( true );
        } else {
            echo json_encode( false );
        }

        exit;
    }
}


global $RHSRegister;
$RHSRegister = new RHSRegister();
