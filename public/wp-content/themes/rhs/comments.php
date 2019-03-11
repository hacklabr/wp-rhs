<?php
/**
 * Tema para exibir Comments.
 *
 * A área da página que contém os comentários atuais
 * E o formulário de comentário. A exibição real dos comentários é
 * Manipulado por um callback em RHS_comment () que é
 * Localizado no arquivo functions.php.
 *
 * @package WordPress
 * @subpackage RHS
 */

if (post_password_required()) {
    return;
} ?>
<div class="row">
	<!-- Container -->
	<div class="col-xs-12 col-md-12" id="comments">
		<!--show the form-->
		<h2 class="titulo-quantidade text-uppercase"><i class="fa fa-comments-o" aria-hidden="true"></i> <?php comments_number(__('não há Comentários', 'rhs'), __('1 Comentário','rhs'), __('% Comentários','rhs') );?></h2>
		<?php if('open' == $post->comment_status) : ?>
			<div id="respond" class="clearfix">        
			    <?php if(get_option('comment_registration') && !$user_ID) : ?>
					<p>
					<?php printf( __( 'Faça %slogin%s para comentar e recomendar este post a outros usuários da rede.', 'rhs'), "<a href='" . get_option('home') . "/logar?redirect_to=" . urlencode(get_permalink()) ."'>", "</a>" ); ?>
					</p>        
			    <?php else : ?>
			    <form autocomplete="off" action="<?php echo get_option('siteurl'); ?>/wp-comments-post.php" method="post" id="form-comentario" class="clearfix">
			        <div class="form-group">
			        <?php comment_id_fields(); ?>
 					<textarea name="comment" id="comment" tabindex="1" required class="form-control" rows="4" placeholder="<?php _e('Digite seu comentário aqui.', 'rhs'); ?>"></textarea>
					</div>
					<button id="submit" class="btn btn-info btn-comentar" type="submit" name="submit">Comentar</button>
					<?php cancel_comment_reply_link('Cancelar'); ?>
			        <?php do_action('comment_form', $post->ID); ?>
			    </form>
			    <?php endif; ?>
			</div>
		<?php endif; ?>

	    <?php if (have_comments()) : ?>

            <?php wp_list_comments(array('callback' => 'RHS_Comentarios')); ?>

	        <?php if (get_comment_pages_count() > 1 && get_option('page_comments')) : ?>
	            <nav id="comment-nav-below" class="navigation" role="navigation">
	                <div class="nav-previous">
	                    <?php previous_comments_link( _e('&larr; Anterior', 'rhs')); ?>
	                </div>
	                <div class="nav-next">
	                    <?php next_comments_link(_e('Próximo &rarr;', 'rhs')); ?>
	                </div>
	            </nav>
	        <?php endif; // check for comment navigation ?>

	        <?php elseif (!comments_open() && '0' != get_comments_number() && post_type_supports(get_post_type(), 'comments')) : ?>
	            <p class="nocomments"><?php _e('Os comentários estão desabilitados para este post.', 'rhs'); ?></p>
	    <?php endif; ?>
	</div>
</div>