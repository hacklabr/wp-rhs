<?php



Class Carrossel {

    
    static function __init() {
    
    
        add_action('manage_posts_custom_column', array('Carrossel', 'select'), 10, 2);
        add_filter('manage_posts_columns',array('Carrossel', 'add_column'));
        add_action('manage_noticias_posts_custom_column', array('Carrossel', 'select'), 10, 2);
        add_action('load-edit.php', array('Carrossel', 'JS'));
        add_action('load-edit-pages.php', array('Carrossel', 'JS'));
        
        add_action('wp_ajax_destaque_add', array('Carrossel', 'add'));
        add_action('wp_ajax_destaque_remove', array('Carrossel', 'remove'));
        
        add_action('pre_get_posts', array('Carrossel', 'pre_get_posts'));
        add_action( 'restrict_manage_posts', array('Carrossel', 'admin_filter_area'));
        add_filter( 'parse_query', array('Carrossel' ,'filter_post'));
    
    
    }

    static function add_column($defaults){
        global $post_type;
        if ('post' == $post_type || 'noticias' == $post_type || 'imprensa' == $post_type)
            $defaults['destaques'] = 'Carrossel';
        return $defaults;
    }

    static function select($column_name, $id){

        if ($column_name=="destaques"){
            $highlighted = get_post_meta($id, "_home", true) >= 1 ?  "checked" : "";
        ?>  
            <input type="checkbox" class="carrossel_button" id="carrossel_<?php echo $id; ?>" <?php echo $highlighted; ?>>
        <?php
        }
    }

    static function JS() {
        wp_enqueue_script('carrossel', get_template_directory_uri() . '/inc/carrossel/admin.js', array('jquery'));
        wp_enqueue_style('carrossel', get_template_directory_uri() . '/inc/carrossel/carrossel.css');
        wp_localize_script('carrossel', 'hacklab', array('ajaxurl' => admin_url('admin-ajax.php') ));
    }
    
    function add() {
        self::move_order_up();
        update_post_meta($_POST['post_id'], '_home', 1);
        echo 'ok';
        die;
    }

    function remove() {
        delete_post_meta($_POST['post_id'], '_home');
        self::fix_order();
        echo 'ok';
        die;
    }
    
    static function fix_order($from = 1) {
    
        global $wpdb;
        $posts = $wpdb->get_results("SELECT * FROM $wpdb->postmeta WHERE meta_key = '_home' AND meta_value >= $from ORDER BY meta_value ASC, meta_id DESC");
        
        foreach ($posts as $p) {
            $wpdb->update($wpdb->postmeta, ['meta_value' => $from], ['meta_id' => $p->meta_id]);
            $from ++;
        }
    
    }
    
    static function move_order_up($from = 1) {
    
        global $wpdb;
        $wpdb->query("UPDATE $wpdb->postmeta SET meta_value = (meta_value + 1) WHERE meta_key = '_home' AND meta_value >= $from");
    
    }
    
    
    static function move_post_order($post_id, $from, $to) {
        global $wpdb;
        
        if ($from < $to) {
            
            $wpdb->query("UPDATE $wpdb->postmeta SET meta_value = (meta_value - 1) WHERE meta_key = '_home' AND meta_value > $from AND meta_value <= $to");
            update_post_meta($post_id, '_home', $to);
            
        } elseif ($to < $from) {
            
            $wpdb->query("UPDATE $wpdb->postmeta SET meta_value = (meta_value + 1) WHERE meta_key = '_home' AND meta_value >= $to");
            update_post_meta($post_id, '_home', $to);
        
        } else {
            return;
        }
        
        self::fix_order();
    
    }
       
    static function pre_get_posts($wp_query) {

        if (!$wp_query->is_main_query())
            return $wp_query;
        
        if (is_front_page()) {
            global $wpdb;
            $wp_query->query_vars['post__not_in'] = $wpdb->get_col("SELECT post_id FROM $wpdb->postmeta WHERE meta_key = '_home' AND meta_value = 1");
        
        }

    }
    
    static function get_posts() {
        return new WP_Query( 'posts_per_page=-1&meta_key=_home&orderby=meta_value_num&order=asc&ignore_sticky_posts=1' );
    }
    
    /**
     * Criando Checkbox para filtros em listagem de posts
     */
    static function admin_filter_area() {
        if( get_current_screen()->post_type === "post" ) {
            $current_value = isset($_GET['rhs-filter-carousel']) ? $_GET['rhs-filter-carousel'] : '';
            ?>
            <label for="rhs-filter-carousel">
                Posts no Carrossel
                <input type="checkbox" id="rhs-filter-carousel" name="rhs-filter-carousel"
                       value="rhs-filter-carousel" <?php echo 'rhs-filter-carousel' == $current_value ? 'checked="checked"' : '' ?> >
                </label>
            <?php
        }
    }

    /**
     * Filtro de posts que estão no Carossel
     */
    static function filter_post($query){
        global $pagenow;
        
        if (is_admin() && $pagenow == 'edit.php' && isset($_GET['rhs-filter-carousel']) && $_GET['rhs-filter-carousel'] != '') {
            $query->query_vars['meta_key'] = '_home';
        }
    }


}


add_action('init', array('Carrossel', '__init'));

require_once('metabox.php');
