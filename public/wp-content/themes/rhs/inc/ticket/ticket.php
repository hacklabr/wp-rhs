<?php
require_once __DIR__ . "./../traits/emailValidator.php";

if( ! class_exists( 'WP_List_Table' ) ) {
    require_once( ABSPATH . 'wp-admin/includes/class-wp-list-table.php' );
}
class RHSTicket extends RHSMessage {
    use emailValidator;

    const POST_TYPE = 'tickets';
    const TAXONOMY = 'tickets-category';
    const NOT_RESPONSE = 'not_response';
    const OPEN = 'open';
    const CLOSE = 'close';
    const CAPABILITIES = 'capabilities';
    const COMMENT_STATUS = 'ticket-status';
    private static $instance;
    var $post_status = [];

    function __construct() {
        
        $this->post_status = $this->get_custom_post_status();
        
        add_action('init', array( &$this, "register_post_type" ));
        add_action('init', array( &$this, "register_taxonomy" ));
        add_action( 'init', array( &$this, 'init' ) );
        add_action('add_meta_boxes', array( &$this, "add_meta_boxes"));
        add_action('admin_head', array( &$this, 'css'));
        add_action( 'restrict_manage_posts', array( &$this, 'admin_filters') );
        add_action( 'save_post', array(&$this,  'save_wp_editor_fields') );
        //add_filter( 'map_meta_cap', array( &$this, 'ticket_post_cap' ), 10, 4 );
        add_action( 'admin_menu', array( &$this, 'remove_meta_boxes') );
        add_action( self::TAXONOMY.'_edit_form_fields', array( &$this, 'edit_category_field') );
        add_action( self::TAXONOMY.'_add_form_fields',array( &$this, 'new_category_field') );
        add_action( 'edited_'.self::TAXONOMY, array( &$this,'save_tax_meta'), 10, 2 );
        add_action( 'create_'.self::TAXONOMY, array( &$this,'save_tax_meta'), 10, 2 );
        
        // registra post status
        add_action('init', array(&$this, 'register_post_status'));
        add_action( 'admin_footer-post.php', array( &$this, 'add_status_dropdown' ) );
        
        // filtra listagem no admin
        add_filter( 'parse_query', array(&$this, 'admin_parse_query') );
        
        // colunas no admin
        add_filter('manage_posts_columns', array(&$this, 'custom_columns_head'));
        add_action('manage_posts_custom_column', array(&$this, 'custom_columns_content'), 10, 2);


        // add_action('admin_footer', array(&$this, 'remove_column_span_comments')); // Not used by now
    }

    function remove_column_span_comments() {
        echo "
            <script type='text/javascript'>
                jQuery( function( $ ) {
                    $('body.edit-comments-php #wpbody-content .wrap ul.subsubsub li.moderated').remove();
                    $('body.edit-comments-php #wpbody-content .wrap ul.subsubsub li.all').remove();
                
                });
            </script>";
    }
    
    function register_post_status() {
        // Registra post status
		foreach ( $this->post_status as $post_status => $args ) {
			register_post_status( $post_status, $args );
		}
    }
    
    function add_status_dropdown() {
		global $post;
		if ( $post->post_type == self::POST_TYPE ) {

			$js                  = '';
			$change_status_label = false;

			foreach ( $this->post_status as $post_status => $args ) {

				$selected = '';

				if ( $post->post_status == $post_status ) {
					$selected            = 'selected';
					$change_status_label = $args['label'];

				}

				$js .= '$("select#post_status").append("<option value=\'' . $post_status . '\' ' . $selected . '>' . $args['label'] . '</option>");';

			}

			if ( $change_status_label !== false ) {
				$js .= '$("#post-status-display").append("' . $change_status_label . '");';
			}

			echo '
                <script>
                    jQuery(document).ready(function($){
                        ' . $js . '
                    });
                </script>
            ';
		}
	}
    
    function custom_columns_head($defaults) {
        
        global $typenow;
        
        if ($typenow != self::POST_TYPE)
            return $defaults;
        
        $defaults['autor'] = 'Autor'; // a chave autor em portugues pq se for em ingles ele monta a coluna com o metodo padrao do wp
        $defaults['email'] = 'Email';
        $defaults['member_since'] = 'Membro desde';
        $defaults['responsavel'] = 'Responsável';
        
        return $defaults;   
    }
    
    function custom_columns_content($column_name, $post_ID) {
        
        $author = get_userdata(get_post_field( 'post_author', $post_ID ));
        #$defaultAuthor = $this->getUserDefault();
        $isNotLoggedAuthor = get_post_meta($post_ID, '_not_logged_user', true) == '1';
        
        if ($column_name == 'autor') {
            if ($isNotLoggedAuthor || !is_object($author)) {
                echo get_post_meta($post_ID, '_author_name', true);
            } else {
                echo '<a href="' . get_author_posts_url($author->ID) . '">';
                echo $author->display_name;
                echo '</a>';
                
            }
                
        } elseif ($column_name == 'email') {
            echo $isNotLoggedAuthor || !is_object($author) ? get_post_meta($post_ID, '_author_email', true) : $author->user_email;
        } elseif ($column_name == 'member_since') {
            echo $isNotLoggedAuthor || !is_object($author) ? '--' : $author->user_registered;
        } elseif ($column_name == 'responsavel') {
            $u_id = get_post_meta($post_ID, '_responsavel', true);
            if ($u_id) {
                $u = get_userdata($u_id);
                echo $u->display_name;
            }
        }
        
    }
    
    /**
     * Adiciona campo de 'Usuário Responsavél' na categoria do ticket na inserção
     * @param $term
     */
    function save_tax_meta( $term_id , $taxonomy ){
        if(isset( $_POST['term_meta']['category_user'])){
            $term_meta = array();
            $term_meta['category_user'] = $_POST['term_meta']['category_user'] ;
            add_term_meta($term_id, 'user', $_POST['term_meta']['category_user'], true);

            if ( !  add_term_meta($term_id, 'user', $_POST['term_meta']['category_user'], true) ) {

                update_term_meta($term_id, 'user', $_POST['term_meta']['category_user']);
            }
        }
    }

    function new_category_field( $term ){
        $args = array(
            'role__in' => ['administrator', 'editor'],
            'orderby' => 'display_name',
        );
        $subscribers = get_users($args);
        ?>

        <div class="form-field term-parent-wrap">
            <label for="term_meta[category_user]">Usuário Responsavél</label>
            <select class="postform" name="term_meta[category_user]" id="term_meta[category_user]">
                <option value="">-- Selecione --</option>
                <?php foreach ($subscribers as $subscriber){ ?>
                <option value="<?php echo $subscriber->ID ?>" ><?php echo $subscriber->display_name ?> (<?php echo $subscriber->user_email ?>)</option>
                <?php } ?>
            </select>
        </div>
        <?php
    }
    /**
     * Adiciona campo de 'Usuário Responsavél' na categoria do ticket na edição
     * @param $term
     */
    function edit_category_field( $term ){
        $term_meta = '';
        if($term instanceof WP_Term){
            $term_id = $term->term_id;
            $term_meta = get_term_meta($term_id, 'user', true );
        }
        $args = array(
            'role__in' => ['administrator', 'editor'],
            'orderby' => 'display_name',
        );
        $subscribers = get_users($args);
        ?>
        <tr class="form-field term-parent-wrap">
            <th scope="row">
                <label for="parent">Usuário Responsavél</label>
            </th>
            <td>
                <select class="postform" name="term_meta[category_user]" id="term_meta[category_user]">
                    <option value="">-- Selecione --</option>
                    <?php foreach ($subscribers as $subscriber){ ?>
                        <option value="<?php echo $subscriber->ID ?>" <?php echo ($term_meta == $subscriber->ID) ? 'selected': ''?>><?php echo $subscriber->display_name ?> (<?php echo $subscriber->user_email ?>)</option>
                    <?php } ?>
                </select>
            </td>
        </tr>

        <?php
    }
    
    /**
     * É chamado quando o formulário de contato é enviado
     */
    public function trigger_by_post() {
        $_isPOST = $_SERVER['REQUEST_METHOD'] === 'POST';
        if (!$_isPOST)
            return;

        if (isset($_POST['email']) && $this->is_email_blacklisted($_POST['email']))
            return;

        if (( isset($_POST['surname']) && !empty($_POST['surname']) ) ||
            ( isset($_POST['phone']) && !empty($_POST['phone']) ) ) {
            return;
        }

        if (! empty( $_POST['ticket_user_wp'] ) && $_POST['ticket_user_wp'] == $this->getKey() ) {
            if ( ! $this->validate_by_post_insert() ) {
                return;
            }
            
            $defaultAuthor = false;
            if(!is_user_logged_in()){
                $author = $this->getUserDefault();
                $defaultAuthor = true;
            } else {
                $author = wp_get_current_user();
            }
            
            $name = $defaultAuthor ? $_POST['name'] : $author->display_name;
             
            $email = $defaultAuthor ? $_POST['email'] : $author->user_email;
            
            if ($defaultAuthor) {
                $estado = $_POST['estado'];
                $municipio = $_POST['municipio'];
            } else {
                $ufmun = get_user_ufmun($author->ID);
                $estado = $ufmun['uf']['id'];
                $municipio = $ufmun['mun']['id'];
            }

            $this->insert(
                $name,
                $email,
                $estado,
                $municipio,
                $_POST['category'],
                $_POST['subject'],
                $_POST['message'],
                $defaultAuthor);
        }
        

        if ( ! empty( $_POST['add_comment_ticket_wp'] ) && $_POST['add_comment_ticket_wp'] == $this->getKey() ) {

            if ( ! $this->validate_by_post_comment() ) {
                return;
            }

            $this->insert_comment(
                    $_POST['comment_post_ID'],
                    get_current_user_id(),
                    wp_get_current_user()->user_login,
                    wp_get_current_user()->user_email,
                    wp_get_current_user()->user_url, 
                    $_POST['comment']);

            $this->set_alert('<i class="fa fa-check"></i> Comentário salvo');
            wp_redirect(get_permalink($_POST['comment_post_ID']));
            exit;
        }
    }
    /**
     * Insere contato
     * @param $name
     * @param $email
     * @param $subject
     * @param $state
     * @param $city
     * @param $message
     * @param $category
     * @param int $userId
     */
    public function insert( $name, $email, $state, $city, $category, $subject, $message, $defaultAuthor = false ) {
        
        if($defaultAuthor){
            $author = $this->getUserDefault();
        } else {
            $author = wp_get_current_user();
        }
        
        $dataPost = array(
            'post_title'    => wp_strip_all_tags( $subject ),
            'post_content'  => $message,
            'post_status'   => self::NOT_RESPONSE,
            'post_author'   => $author->ID,
            'post_type'     => self::POST_TYPE,
            'comment_status' => 'open'
        );

        $post_ID = wp_insert_post($dataPost, true);
        
        if ( $post_ID instanceof WP_Error ) {
            foreach ( $post_ID->get_error_messages() as $error ) {
                $this->set_messages( $error, false, 'error' );
            }
            return;
        }
        
        // insere metadados
        add_post_meta($post_ID, '_author_name', $name);
        add_post_meta($post_ID, '_author_email', $email);
        add_post_ufmun_meta($post_ID, $city, $state);
        
        // salvamos também a data de registro do usuário logado
        add_post_meta($post_ID, '_author_registered', $author->user_registered);
         
        // usuário logado?
        add_post_meta($post_ID, '_not_logged_user', $defaultAuthor);
        
        // insere categoria do ticket
        wp_set_object_terms( $post_ID, (int) $category, self::TAXONOMY );
        
        // atualiza contagem de tickets na categoria
        
        // Salva o usuário padrão setado na categoria como o responsável do ticket
        // O responsável pode ser alterado depois, via metabox.
        // o term_meta do usuário padrão da categoria serve apenas para esta setagem na hora que o ticket é criado
        $responsavel_padrao = get_term_meta($category, 'user', true);
        if ($responsavel_padrao) add_post_meta($post_ID, '_responsavel', $responsavel_padrao);
        
        do_action('rhs_new_ticket_posted', $post_ID, $message, $responsavel_padrao, $defaultAuthor, $author);
        
        $this->set_alert(   '<i class="fa fa-check "></i> Contato enviado com sucesso!');
        
        wp_redirect(home_url('contato'));
        exit;
    }
    /**
     * Função recursiva que retorna categorias baseado nos pais formatadas
     * @param int $categories
     * @param array $option
     * @param int $parent
     *
     * @return array
     */
    public function category_tree_option($categories = 0, &$option = array(), $parent = 0)
    {
        if($categories == 0){
            $categories = get_terms(self::TAXONOMY, array('hide_empty' => false,'parent' => 0));
        }
        $prefix = str_repeat("—", $parent);
        ++$parent;
        foreach($categories as $key => &$value){
            $option[$value->term_id] = (!$prefix) ? $value->name : $prefix.' '.$value->name;
            $children = get_terms(self::TAXONOMY, array('hide_empty' => false,'parent' => 0,'parent'=>$value->term_id));
            if($children){
                $this->category_tree_option($children, $option, $parent);
            }
        }
        return $option;
    }

    public function category_parent(){

        return get_terms(self::TAXONOMY, array('hide_empty' => false,'parent' => 0, 'orderby'    => 'term_id'));

    }


    /**
     * Retorna usuario padrão, caso não esteja logado
     * @return bool|false|object|WP_User
     */
    public function getUserDefault(){
        $login = 'rhs_author_default_ticket';
        $user = get_user_by('login', $login);
        if($user){
            return $user;
        }
        $user_data = array(
            'user_pass' => wp_generate_password(),
            'user_login' => $login,
            'user_nicename' => 'author-default-ticket',
            'user_url' => '',
            'user_email' => 'faqrhs@gmail.com',
            'display_name' => 'Autor padrão de ticket',
            'nickname' => 'autor-default',
            'first_name' => 'Autor Ticket',
            'user_registered' => current_time('mysql'),
            'role' => get_option('default_role')
        );
        $user_id = wp_insert_user( $user_data );
        return get_userdata($user_id);
    }

    /**
     * Valida campos por backend ao inserir o comentário do contato
     * @return bool
     */
    private function validate_by_post_comment() {
        $this->clear_messages();
        if ( ! array_key_exists( 'comment_post_ID', $_POST ) ) {
            $this->set_alert('<i class="fa fa-exclamation-triangle "></i> Sem informação do ticket de suporte!' );
            return false;
        }
        if ( ! array_key_exists( 'comment', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Preencha com seu comentário!' );
            return false;
        }

        return true;
    }

    /**
     * Valida compos por backend ao inserir o contato
     * @return bool
     */
    private function validate_by_post_insert() {
        $this->clear_messages();
        if ( ! array_key_exists( 'name', $_POST ) ) {
            $this->set_alert('<i class="fa fa-exclamation-triangle "></i> Preencha o seu nome!' );
            return false;
        }
        if ( ! array_key_exists( 'email', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Preencha o seu email!' );
            return false;
        }
        if ( ! array_key_exists( 'subject', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Preencha o assunto do contato!' );
            return false;
        }
        if ( ! array_key_exists( 'estado', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Selecione o seu estado!' );
            return false;
        }
        if ( ! array_key_exists( 'municipio', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Selecione o sua cidade!' );
            return false;
        }
        if ( ! array_key_exists( 'category', $_POST ) ) {
            $this->set_alert(   '<i class="fa fa-exclamation-triangle "></i> Selecione sobre qual categoria é o assunto!' );
            return false;
        }
        return true;
    }
    /**
     * Remove meta box pad~rao dos comentários
     */
    function remove_meta_boxes() {
        remove_meta_box('commentsdiv', self::POST_TYPE, 'normal');
    }

    function insert_comment($postId, $author_id, $author_login, $author_email, $author_url, $content){

        $post = get_post($postId);
        
        $time = current_time('mysql');

        $data = array(
            'comment_post_ID' => $postId,
            'comment_author' => $author_login,
            'comment_author_email' => $author_email,
            'comment_author_url' => $author_url,
            'comment_content' => $content,
            'comment_type' => '',
            'comment_parent' => 0,
            'user_id' => $author_id,
            'comment_author_IP' => $_SERVER['REMOTE_ADDR'],
            'comment_agent' => $_SERVER['HTTP_USER_AGENT'],
            'comment_date' => $time,
            'comment_approved' => 1
        );

        $comment_id = wp_insert_comment($data);

        do_action('rhs_ticket_replied', $post->post_author, $postId, $content);
    
        global $wpdb;
        $wpdb->update( $wpdb->comments, array('comment_approved' => self::COMMENT_STATUS), array( 'comment_ID' => $comment_id ));
    }

    /**
     * Salvando ticket pelo admin
     */
    function save_wp_editor_fields(){
        global $post;

        if(!empty($_POST['editor_box_comments'])){

            $user = new RHSUser(get_userdata($_POST['user_ID']));
            $user_from_contact = new RHSUser(get_userdata($_POST['post_author']));

            $this->insert_comment(
                $post->ID,
                $user->get_id(),
                $user->get_login(),
                $user->get_email(),
                $user->get_url(),
                wpautop($_POST['editor_box_comments'])
            );

            

            global $wpdb;

            // Como teve uma resposta, marcamos o ticket como aberto
            $wpdb->update($wpdb->posts, ['post_status' => self::OPEN], ['ID' => $post->ID]);
            // para disparar hooks de mudança de status que possamos usar
            wp_transition_post_status( self::OPEN, $_POST['original_post_status'], $post );
        }
        
        if (isset($_POST['_responsavel'])) {
            update_post_meta($post->ID, '_responsavel', $_POST['_responsavel']);
        }
        
    }
    /**
     * Status do post
     * @return array
     */
    function get_custom_post_status() {
        return array(
            self::NOT_RESPONSE => array(
                'label'                     => 'Não Repondido',
                'public'                    => true,
                'exclude_from_search'       => false,
                'show_in_admin_all_list'    => true,
                'show_in_admin_status_list' => true,
                'label_count'               => _n_noop( 'Não Repondido <span class="count">(%s)</span>',
                    'Não Repondidos <span class="count">(%s)</span>' ),
            ),
            self::OPEN => array(
                'label'                     => 'Em Aberto',
                'public'                    => true,
                'exclude_from_search'       => false,
                'show_in_admin_all_list'    => true,
                'show_in_admin_status_list' => true,
                'label_count'               => _n_noop( 'Em Aberto <span class="count">(%s)</span>',
                    'Em Aberto <span class="count">(%s)</span>' ),
            ),
            self::CLOSE => array(
                'label'                     => 'Fechado',
                'public'                    => true,
                'exclude_from_search'       => false,
                'show_in_admin_all_list'    => true,
                'show_in_admin_status_list' => true,
                'label_count'               => _n_noop( 'Fechado <span class="count">(%s)</span>',
                    'Fechados <span class="count">(%s)</span>' ),
            )
        );
    }
    /**
     * Registra status caso for ticket
     */
    function init() {
        global $post;
        $post_type = '';
        if(!empty($_GET['post_type'])){
            $post_type = $_GET['post_type'];
        }
        if(!$post && !empty($_GET['post'])){
            $post = get_post($_GET['post']);
            if($post){
                $post_type = $post->post_type;
            }
        }
        if($post_type == self::POST_TYPE){
            foreach ( $this->post_status as $post_status => $args ) {
                register_post_status( $post_status, $args );
            }
        }
        $category = array();
    }
    /**
     * Adiciona filtro de categoria e responsável na listagem do ticket
     */
    function admin_filters() {
        global $typenow, $post, $post_id;
        if( $typenow == self::POST_TYPE ){
            $tax_obj = get_taxonomy(self::TAXONOMY);
            $tax_name = $tax_obj->name;
            $terms = get_terms($tax_name, array('hide_empty' => false));
            
            $dropDownArgs = array(
            	'show_option_all'    => 'Categorias',
            	'orderby'            => 'ID',
            	'order'              => 'ASC',
            	'show_count'         => 1,
            	'hide_empty'         => 0,
            	'selected'           => (isset($_GET[$tax_name])) ? $_GET[$tax_name] : '',
            	'hierarchical'       => 1,
            	'name'               => self::TAXONOMY,
            	'id'                 => self::TAXONOMY,
            	'class'              => 'postform',
            	'depth'              => 0,
            	'tab_index'          => 0,
            	'taxonomy'           => self::TAXONOMY,
            	'hide_if_empty'      => false,
            	'value_field'	     => 'slug',
            );
            
            wp_dropdown_categories($dropDownArgs);
            
            $current = isset($_GET['responsavel']) ? $_GET['responsavel'] : null; 
        
            $args = array(
                'role__in' => ['administrator', 'editor'],
                'orderby' => 'display_name',
            );
            $subscribers = get_users($args);
            ?>
                <select class="postform" name="responsavel" id="responsavel">
                    <option value="">Responsável</option>
                    <?php foreach ($subscribers as $subscriber){ ?>
                        <option value="<?php echo $subscriber->ID ?>" <?php selected($subscriber->ID, (int) $current); ?>><?php echo $subscriber->display_name ?></option>
                    <?php } ?>
                </select>

            <?php
            
            
        }
    }
    
    /**
     * Filtra listagem do admin
     */ 
    function admin_parse_query($query) {
        global $pagenow;
        $current_page = isset( $_GET['post_type'] ) ? $_GET['post_type'] : '';

        if ( is_admin() && 
        self::POST_TYPE == $current_page &&
        'edit.php' == $pagenow && 
        isset( $_GET['responsavel'] ) && 
        $_GET['responsavel'] != '') {

        $responsavel = $_GET['responsavel'];
        $query->query_vars['meta_key'] = '_responsavel';
        $query->query_vars['meta_value'] = $responsavel;
        $query->query_vars['meta_compare'] = '=';
        }
    }
    
    /**
     * Adiciona as 2 meta boxs do ticket
     */
    function add_meta_boxes() {
        global $post;
        add_meta_box('ticket_response', 'Conversação', array( &$this, 'meta_box_response'), self::POST_TYPE, 'normal', 'default');
        add_meta_box('ticket_wp_editor', 'Enviar Resposta', array( &$this, 'meta_box_comment'), self::POST_TYPE, 'normal', 'default');
        add_meta_box('ticket_responsavel', 'Usuário Responsável', array( &$this, 'meta_box_responsavel'), self::POST_TYPE, 'side', 'default');
    }
    /**
     * Meta box do ticket, para responder o ticket
     * @param $post
     */
    function meta_box_comment($post){
        $editor_id = 'editor_box_comments';
        wp_editor( '', $editor_id, [
            'textarea_rows' => 5,
        ] );
        ?>
        
        <button type="submit" class="btn btn-default">Enviar</button>
        <?php
    }
    /**
     * Meta box do ticket, para visualização das respostas
     * @param $post
     *
     * @return string
     */
    function meta_box_response($post) {
        $comments = get_comments(array('post_id'=>$post->ID,'order'=>'asc', 'status' => self::COMMENT_STATUS));
        
        $user_author = get_userdata( $post->post_author );
        // Título do ticket e mensagem original
        echo '<h1>Contato #'.$post->ID . ': ' . $post->post_title.'</h1>';
        ?>
        <div class="comments-ticket author">
            <div class="avatar">
                <?php echo get_avatar($post->post_author); ?>
            </div>
            <span>(<?php echo date('d/m/Y á\s H:i',strtotime($post->post_date)) ?>) <?php echo $user_author->display_name ?>, <?php echo $user_author->user_email ?> <i class="role">(Autor)</i> </span>
            <p><?php echo apply_filters('the_content', $post->post_content); ?></p>
            <div class="clearfix"></div>
        </div>
        <?php
        
        
        foreach ($comments as $comment){
            $isauthor = ($comment->user_id == $post->post_author) ? true : false;
            $user = get_userdata( $comment->user_id );
                ?>
                <div class="comments-ticket <?php echo $isauthor ? 'author' : ''; ?>">
                    <div class="avatar">
                        <?php echo get_avatar($comment->user_id); ?>
                    </div>
                    <span>(<?php echo date('d/m/Y á\s H:i',strtotime($comment->comment_date)) ?>) <?php echo $user->display_name ?>, <?php echo $user->user_email ?> <i class="role"><?php echo ($isauthor) ? '(Autor)' : '(Editor)'; ?></i> </span>
                    <p><?php echo $comment->comment_content; ?></p>
                    <div class="clearfix"></div>
                </div>
                <?php
        }
        echo "<div class='clearfix'></div>";
        return '';
    }
    
    function meta_box_responsavel($post) {
        
        $current = get_post_meta($post->ID, '_responsavel', true);
        
        $args = array(
            'role__in' => ['administrator', 'editor'],
            'orderby' => 'display_name',
        );
        $subscribers = get_users($args);
        ?>
            <label for="parent">Usuário Responsavél</label>
            <select class="postform" name="_responsavel" id="_responsavel">
                <option value="">-- Selecione --</option>
                <?php foreach ($subscribers as $subscriber){ ?>
                    <option value="<?php echo $subscriber->ID ?>" <?php selected($subscriber->ID, (int) $current); ?>><?php echo $subscriber->display_name ?></option>
                <?php } ?>
            </select>

        <?php
    }
    
    /**
     * Registra novo tipo de post
     */
    function register_post_type()
    {
        $labels = array(
            'name' => 'Contatos',
            'singular_name' => 'Contato',
            'add_new' => 'Adicionar Novo',
            'add_new_item' =>'Adicionar Contato',
            'edit_item' => 'Editar',
            'new_item' => 'Novo Contato',
            'view_item' => 'Visualizar',
            'search_items' => 'Pesquisar',
            'not_found' => 'Nenhum ticket encontrado',
            'not_found_in_trash' => 'Nenhum Contato encontrado na lixeira',
            'parent_item_colon' => 'Contato acima:',
            'menu_name' => 'Contatos'
        );
        $args = array(
            'labels' => $labels,
            'hierarchical' => false,
            'supports' => array('title'),
            'taxonomies' => array(self::TAXONOMY),
            'public' => true,
            'show_ui' => true,
            'show_in_menu' => true,
            'menu_position' => 5,
            'show_in_nav_menus' => false,
            'publicly_queryable' => true,
            'exclude_from_search' => true,
            'has_archive' => false,
            'query_var' => true,
            'can_export' => true,
            'rewrite' => true,
            'capability_type' => 'post',
            'menu_icon' => 'dashicons-tickets'
        );
        register_post_type(self::POST_TYPE, $args);
        
        // removemos depois porque se passar um array vazio ele usa os valores padrão
        remove_post_type_support(self::POST_TYPE, 'title');
        
    }
    /**
     * Registra nova taxonomia
     */
    function register_taxonomy()
    {
        $labels = array(
            'name' =>'Categorias',
            'singular_name' => 'Categoria',
            'search_items' => 'Buscar Categoria',
            'all_items' => 'Todas as Categorias',
            'parent_item' => 'Categorias Acima',
            'parent_item_colon' => 'Categorias Acima:',
            'edit_item' => 'Editar Categoria',
            'update_item' => 'Atualizar Categorias',
            'add_new_item' => 'Adicionar Nova Categoria',
            'new_item_name' => 'Novo nome de Categoria',
        );
        register_taxonomy(
            self::TAXONOMY,
            self::POST_TYPE,
            array(
                'hierarchical' => true,
                'labels' => $labels,
                'show_ui' => true,
                'query_var' => true,
                'rewrite' => false
            )
        );
    }
    /**
     * Css para a caixa de comentários do ticket na administração
     */
    function css() {
        echo '<style>
            #ticket_wp_editor .inside .btn{
                margin-top: 30px;
                padding: 5px; 
                width: 150px;
            }
            .comments-ticket{
                box-shadow: 2px 1px 2px 0 #777;
                border-radius: 7px;
                padding: 20px;
                background: rgba(241, 241, 241, 0.19);
                width: 80%;
                float: left;
                   margin-top: 10px;
            }
            .comments-ticket > .avatar{
                float: left;
                display: inline-block;
                height: 60px;
                width: 60px;
                object-fit: cover;
            }
            .comments-ticket > .avatar > img{
                width: 100%;
                height: 100%;
            }
            .comments-ticket > span{
                margin-left: 15px;
                font-weight: 600;
                font-style: italic;
                font-size: 12px;
                float: left;
                width: calc(100% - 75px);
            }
            .comments-ticket > span > i{
                color: #bb0d0d;
            }
            .comments-ticket > span > .to-author{
                float: right;
                text-decoration: none;
                margin-top: -13px;
                margin-right: -10px;
                color: #04b123;
            }
            .comments-ticket > p{
                margin-left: 15px;
                margin-top: 3px;
                display: block;
                float: left;
                width: calc(100% - 75px);
            }
            .clearfix{
                clear: both;
            }
            .comments-ticket.author{
                float: right;
                background: rgba(170, 181, 206, 0.27);
            }
            .comments-ticket.author > .avatar{
                float: right;
            }
            .comments-ticket.author > span{
                float: right;
                margin-left: 0;
                margin-right: 15px;
                text-align: right;
            }
            .comments-ticket.author > p{
                float: right;
                margin-left: 0;
                margin-right: 15px;
                text-align: right;
            }
        </style>';
    }

    public function renderTicketInfo($ticked_id) {
        $term_list = wp_get_post_terms($ticked_id, 'tickets-category');
        $term = array(
            "name"   => "--",
            "url"    => get_the_permalink(),
            "status" => $this->getTicketStatus(get_post_status())
        );

        if(is_array($term_list) && !empty($term_list) && $term_list[0] instanceof WP_Term) {
            $term["name"] = $term_list[0]->name;
        }
        ?>
        <tr>
            <th><a href="<?php echo $term["url"]; ?>"> <?php the_time('j \d\e F \d\e Y'); ?> </a></th>
            <th><a href="<?php echo $term["url"]; ?>"> <?php the_title(); ?> </a></th>
            <th><a href="<?php echo $term["url"]; ?>"> <strong> <?php echo $term["name"]; ?> </strong> </a> </th>
            <th><a href="<?php echo $term["url"]; ?>"> <?php echo $term["status"] ?> </a></th>
            <th><a href="<?php echo $term["url"]; ?>" title="Responder"><span class="fa fa-reply"></span></th>
        </tr>
        <?php
    }

    private function getTicketStatus($post_status) {
        $_status = "";
        if( $post_status === 'open')
            $_status = 'Em Aberto';
        elseif( $post_status === 'close')
            $_status = 'Fechado';
        elseif( $post_status === 'not_response')
            $_status = 'Não Repondido';

        return $_status;
    }
}
global $RHSTicket;
$RHSTicket = new RHSTicket();
