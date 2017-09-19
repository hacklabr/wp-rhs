<?php

Class RHSApi  {

    var $apinamespace = 'rhs/v1';

    function __construct() {

        add_action( 'generate_rewrite_rules', array( &$this, 'rewrite_rules' ), 10, 1 );
        add_filter( 'query_vars', array( &$this, 'rewrite_rules_query_vars' ) );
        add_filter( 'template_include', array( &$this, 'rewrite_rule_template_include' ) );
        
        add_action( 'rest_api_init', array( &$this, 'register_rest_route' ) );
        
        // Modifica endpoints nativos
        add_filter( 'rest_prepare_post', array(&$this, 'prepare_post'), 10, 3 );
        add_filter( 'rest_prepare_user', array(&$this, 'prepare_user'), 10, 3 );
     
    }
    
    function register_rest_route() {
        register_rest_route( $this->apinamespace, '/votes/(?P<id>[\d]+)', array(
            'methods' => 'POST',
            'callback' => array( &$this, 'POST_vote' ),
            'args' => array(
                'id' => array(
                    'validate_callback' => function($param, $request, $key) {
                        return is_numeric( $param );
                        }
                )
            ),
            'permission_callback' => function ( $request ) {
                $user_can = current_user_can( 'vote_post', $request['id'] );
                if ($user_can)
                    return true;
                
                global $RHSVote;
                return new WP_Error( $RHSVote->votes_to_text_code, $RHSVote->getTextHelp(), array( 'status' => rest_authorization_required_code() ) );

            }
        ));

        register_rest_route( $this->apinamespace, '/follow/(?P<id>[\d]+)', array(
            'methods'  => 'POST',
            'callback' => array(&$this, 'USER_follow'),
            'args' => array(
                'id' => array(
                    'validate_callback' => function($param, $request, $key) {
                        return is_numeric( $param );
                        }
                )
            ),
            'permission_callback' => function ( $request ) {
                return current_user_can( 'contributor', $request['id'] );   
            }
        ) );

        register_rest_route( $this->apinamespace, '/user/(?P<id>[\d]+)', array(
            'methods' => 'GET',
            'callback' => array(&$this, 'USER_show'),
			'args' => array(
				'id' => array(
					'validate_callback' => function($param, $request, $key) {
                        return is_numeric( $param );
                        }
				),
			)
        ));

        register_rest_route( $this->apinamespace, '/user-device/(?P<device_push_id>[a-zA-Z0-9-]+)', array(
            'methods' => 'POST',
            'callback' => array(&$this, 'add_device_push_id'),
            'args' => array(
                'id' => array(
					'validate_callback' => function($param, $request, $key) {
                        return is_numeric( $param );
                    }
                ),     
            ),
        ));
    }

    function USER_follow($request) {
        global $RHSFollow;
        $data = $RHSFollow->toggle_follow(get_current_user_id(), $request['id']);

        $dataR = [
            'response' => $data,
            'user_id' => get_current_user_id(),
            'follow_id' => $request['id']
        ];

        $response = new WP_REST_Response( $dataR );
        $response->set_status( 200 );

        return $response;
    }

    function POST_vote($request) {
        // Já passamos pela autenticação e permission_callback
        global $RHSVote;
        $data = $RHSVote->add_vote( $request['id'], get_current_user_id() );
        
        $dataR = [
            'response' => $data,
            'post_id' => $request['id'],
            'total_votes' => $RHSVote->get_total_votes($request['id'])
        ];
        
        $response = new WP_REST_Response( $dataR );
        $response->set_status( 200 );

        return $response;
    }
    
    function prepare_post( $data, $post, $context ) {
        global $RHSVote, $RHSNetwork;
        $total_votes = $RHSVote->get_total_votes($post->ID);
        $total_shares = $RHSNetwork->get_post_total_shares($post->ID);
        $data->data['total_votes'] = $total_votes ? $total_votes : 0;
        $data->data['comment_count'] = $post->comment_count;
        $data->data['total_shares'] = $total_shares ? $total_shares : 0;
        return $data;
    }
    
    function prepare_user( $data, $user, $context ) {
        global $RHSVote, $RHSFollow, $RHSFollowPost;
        
        // Se é uma requisição no endpoint /me ou estamos retornando user logado
        // Vamos trazer informações privadas e mais detalhadas
        if (get_current_user_id() == $user->ID) {
            $data->data['posts_followed'] = $RHSFollowPost->get_posts_followed_by_user($user->ID);
        } 
        
        $data->data['followers'] = $RHSFollow->get_user_followers($user->ID);
        $data->data['follows'] = $RHSFollow->get_user_follows($user->ID);
        
        $total_votes = $RHSVote->get_total_votes_by_author($user->ID);
        $data->data['total_votes'] = $total_votes ? $total_votes : 0;
        
        $total_posts = count_user_posts($user->ID);
        $data->data['total_posts'] = $total_posts ? $total_posts : 0;

        $userObj = new RHSUser($user);
        $data->data['formation'] = $userObj->get_formation();
        $data->data['interest'] = $userObj->get_interest();
        $data->data['state'] = $userObj->get_state();
        $data->data['city'] = $userObj->get_city();
        $data->data['links'] = $userObj->get_links();
        
        return $data;
    }
    
    function USER_show($request) {
        $user = $request['id'];
        if (is_wp_error($user)) {
            return $user;
        }

        $user_obj = get_userdata($request['id']) ;
        $userController = new \WP_REST_Users_Controller($user_obj->ID);
        $response = $userController->prepare_item_for_response( $user_obj, $request );
        return rest_ensure_response($response);
    
    }
    
    
    
    ////// Endpoints
    
    function get_teste(WP_REST_Request $request) {
        
        $user = wp_get_current_user();
        $name = $user->display_name;
        
        return array(
            'current_user' => $name, 
            'notification' => 'Você é demais!'
        );
    }
    
    
    
    
    
    
    ////// Callback de login
    
    function rewrite_rules( &$wp_rewrite ) {

        $new_rules = array(
            'api-login-callback/?' => "index.php?rhs_api_callback=1",
        );

        $wp_rewrite->rules = $new_rules + $wp_rewrite->rules;

    }

    function rewrite_rules_query_vars( $public_query_vars ) {

        $public_query_vars[] = "rhs_api_callback";

        return $public_query_vars;

    }

    function rewrite_rule_template_include( $template ) {
        global $wp_query;

        if ( $wp_query->get( 'rhs_api_callback' ) ) {

            // Retorno após fazer autenticação via oauth utilizando a API
            // ver método handle_callback_redirect() da classe WP_REST_OAuth1_UI do plaugin Rest Oauth
            wp_logout();
            die;

        }

        return $template;


    }

    function add_device_push_id($request){
        $current_user = wp_get_current_user();
        $device_push_id = $request['device_push_id'];

        update_user_meta($current_user->ID, 'device_push_id', $device_push_id, $user_meta_value);
        
        $message = [
            'info' => 'Device ID registered', 
            'user' => $current_user, 
            'device_id' => $device_push_id
        ];

        $response = new WP_REST_Response($message);
        $response->set_status(200);

        return $response;
    }

}

global $RHSApi;
$RHSApi = new RHSApi();
