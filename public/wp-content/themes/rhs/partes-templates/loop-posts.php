<?php
if (have_posts()):
    $_is_community = $wp_query->is_tax(RHSComunities::TAXONOMY);
    $class = RHSSearch::get_search_loop_class();
    $extra_class = RHSSearch::is_search_page() ? "busca-posts" : "";
    ?>
	<div class="clearfix masonry <?php echo $extra_class; ?>">
		<div class="grid-sizer"></div> <div class="gutter-sizer"></div>
        <?php
        while( have_posts() ):
            $_show_post = true;
            the_post();

            /*
             * Se estamos na lista de posts da comunidade, exibimos também os posts privados (daquela comunidade).
             * Caso contrário, só listamos posts privados se o autor corrente for o autor do post
             */
            if (!$_is_community) {
                $_is_the_author = get_current_user_id() === get_the_author_meta('ID');
                if ("private" === get_post_status() && ! $_is_the_author) {
                    $_show_post = false;
                }
            }
            
            if ($_show_post): ?>
                <div class="<?php echo $class; ?>"> <?php get_template_part( 'partes-templates/posts'); ?> </div>
                <?php
            endif;
        endwhile;
        ?>
	</div>

	<div class="col-xs-12">
		<div class="text-center">
			<?php paginacao_personalizada(); ?>
		</div>
	</div>

<?php
else:
    get_template_part('partes-templates/none');
endif;