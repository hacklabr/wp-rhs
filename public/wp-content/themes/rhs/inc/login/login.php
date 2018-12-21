<?php

/*
*
* Esta Class implementa as funções necessárias para o Login e uso das reCaptcha.
* Pega a key setada no Painel do Admin (Wordpress).
* Com a Função display_recuperar_captcha() mostra na tela o reCaptcha.
*
*/
class RHSLogin extends RHSMessage {

    private static $instance;

    const META_KEY_LAST_LOGIN = '_last_login';

    function __construct() {

        if ( empty ( self::$instance ) ) {
            add_filter( "login_url", array( &$this, "login_url" ), 10, 3 );
            add_filter( "login_redirect", array( &$this, "login_redirect" ), 10, 3 );
            add_filter( 'wp_login_errors', array( &$this, 'check_errors' ), 10, 2 );
            add_action( 'wp_login', array( &$this, 'save_last_login'));
            add_action( 'login_enqueue_scripts', array( &$this, 'rhs_enqueue_lost' ));
            add_filter( 'login_headerurl', array( &$this, 'rhs_logo_url' ));
            add_filter( 'login_headertitle', array( &$this, 'rhs_logo_title' ));
        }

        self::$instance = true;
    }

    static function login_url( $login_url, $redirect, $force_reauth ) {
        $login_page = home_url(RHSRewriteRules::LOGIN_URL);
        $login_url  = add_query_arg( 'redirect_to', urlencode($redirect), $login_page );

        return $login_url;
    }

    function login_redirect( $redirect_to, $requested_redirect_to, $user ) {        
        
        if(!empty($_POST['currentURL'])){
            $currentURL = $_POST['currentURL'];
        }

        $is_login_via_app = RHSLogin::is_login_via_app();
        if ( empty( $redirect_to) || $is_login_via_app == true) {
            //TODO verificar role do usuário para enviar para a página apropriada
            $redirect_to =  esc_url(home_url());
        } else if(isset($currentURL)) {
            $redirect_to = esc_url( get_home_url() . $currentURL );
        }

        return $redirect_to;
    }

    function login_errors( $errors, $redirect_to ) {

        $_SESSION['login_errors'] = '';
    }
    function check_errors( $errors, $redirect_to ) {

        if ( $errors instanceof WP_Error && ! empty( $errors->errors ) ) {

            if ( $errors->errors ) {

                $this->clear_messages();

                foreach ($errors->get_error_messages() as $error){
                    $this->set_messages($error, false, 'error');
                }
            }

            wp_redirect( home_url(RHSRewriteRules::LOGIN_URL) );
            exit;
        }

        return $errors;
    }

    function save_last_login($login) {
        global $user_ID;
        $user = get_user_by('login', $login);
        update_user_meta($user->ID, self::META_KEY_LAST_LOGIN, current_time('mysql'));
    }
    
    /**
     * get user last login
     * 
     * @param  int $user_id ID do usuário
     * @return false|string  string com a data de utilmo login no formato YYYY-MM-DD HH:ii:ss ou false se não tiver
     */
    static function get_user_last_login($user_id) {
        return get_user_meta($user_id, self::META_KEY_LAST_LOGIN, true);
    }

    /*
    * Lost Password
    */
    function rhs_enqueue_lost() { ?>

        <style type="text/css">
            body{
                background: #003c46 !important;
            }
            #login h1 a {
                background-image: url(<?php echo get_stylesheet_directory_uri(); ?>/assets/images/logo.png);
                height:65px;
                width:320px;
                background-size: initial;
                background-repeat: no-repeat;
            }
            #login .submit .button-primary {
                background: #00b4b9;
                border-color: #00b4b9;
                -webkit-box-shadow: 0 1px 0 #00b4b9;
                box-shadow: 0 1px 0 #00b4b9;
                color: #fff;
                font-weight: bold;
                text-decoration: none;
                text-shadow: 0 -1px 1px #00b4b9, 1px 0 1px #00b4b9, 0 1px 1px #00b4b9, -1px 0 1px #00b4b9;
            }
            #login .submit .button-primary:hover{
                background: #003c46;
                border-color: #003c46;
                -webkit-box-shadow: 0 1px 0 #003c46;
                box-shadow: 0 1px 0 #003c46;
                text-shadow: 0 -1px 1px #003c46, 1px 0 1px #003c46, 0 1px 1px #003c46, -1px 0 1px #003c46;
            }
            #login #nav a, #login #backtoblog a {
                text-decoration: none;
                color: #fff;
            }
            #login #nav a:hover, #login #backtoblog a:hover{
                text-decoration: underline;
            }
            @media only screen and (max-width: 768px){
                #login #nav a, #login #backtoblog a {
                    display: none;
                }
            }
            .login #login #backtoblog{
                display: none;
            }
        </style>
    <?php }

    function rhs_logo_url() {
        return '#';
    }

    function rhs_logo_title() {
        return 'Rede HumanizaSUS';
    }

    //Para uso quando o usuario clica em logar ou registrar no app.
    static function is_login_via_app() {
        //Pega o get do redirect_to caso tenha
        $redirect = (!empty($_GET['redirect_to'])) ? $_GET['redirect_to'] : '';
        //Pega o get do device caso tenha
        $dev = (!empty($_GET['device'])) ? $_GET['device'] : '';

        $a = wp_parse_args( $redirect );
        
        return is_array($a) && isset($a['device']) && $a['device'] == 'mobile-app' || $dev == 'mobile-app' ;
    }


}

global $RHSLogin;
$RHSLogin = new RHSLogin();
