<div class="panel panel-default padding-bottom">
	<div class="panel-heading">
		<div class="row post-titulo">
			<div class="col-xs-9 col-sm-10 col-md-10">
                <?php
                global $RHSNetwork;
                $_post_id = get_the_ID();
                $_post_author_id = get_the_author_meta( 'ID' );
                $_post_ = [
                    'id' => $_post_id,
                    'status' => get_post_status($_post_id),
                    'shares' => $RHSNetwork->get_post_total_shares($_post_id ),
                    'views'  =>  $RHSNetwork->get_post_total_views($_post_id ),
                    'author' => [ 'url' => esc_url( get_author_posts_url($_post_author_id) ),
                                  'href_title' => 'Ver perfil do usuário.'
                    ]
                ];

                the_title( '<h1>', '</h1>' );
                ?>

			</div>

            <div class="col-xs-3 col-sm-2 col-md-2 vdivide">
                <div class="votebox">
                    <?php
                    if( $_post_['status'] != 'private')
                        do_action('rhs_votebox', $_post_id);
                    ?>
                </div>
            </div>

			<div class="col-xs-12">
				<div class="post-categories">
					<?php 
						if(has_category())
							the_category(', ');
					?>
				</div>
			</div>
			<div class="col-xs-12 col-md-12 post-user">
				<div class="post-meta">
					<span class="post-user-date">
						<a href="<?php echo $_post_['author']['url']; ?>" title="<?php echo $_post_['author']['href_title']; ?>">
						    <?php echo get_avatar($_post_author_id,33); ?>
						</a>
						<span class="usuario">
							<a href="<?php echo $_post_['author']['url']; ?>" title="<?php echo $_post_['author']['href_title']; ?>">
								<?php the_author(); ?>
							</a>
						</span>
					</span>
					<span class="post-date text-uppercase">
						<i class="fa fa-calendar" aria-hidden="true"></i> <?php the_time('d/m/Y'); ?>
					</span>
                    <?php if(is_user_logged_in()) { ?>
                        <span class="post-user-edit">
                            <?php edit_post_link( __( 'Editar Post', 'rhs' ), '<span class="divisor text-uppercase">', '</span>', null, 'btn' ); ?>
                        </span>
                    <?php } ?>

					<div class="pull-right share share-wrap col-xs-5 col-md-5">
                    <div class="hidden-print <?php if(!is_user_logged_in()){ ?>pull-right<?php } ?>">
                        <?php if(is_user_logged_in()) { ?>
                            <div class="col-xs-4 col-md-4 <?php echo $_post_['status']; ?>">
                                <?php do_action('rhs_follow_post_box', $_post_id); ?>
                            </div>
                        <?php } ?>
							<?php if( $_post_['status'] == 'publish') : ?>

                                <div class="<?php if(is_user_logged_in()) { ?>col-xs-3 col-md-4<?php }else{ ?>col-xs-5 col-md-5<?php } ?> view-shares">
                                    <div class="col-xs-6 col-md-6 views">
                                        <span class="num" title="Visualização"> <?php echo $_post_['views']; ?> </span>
                                        <span class="glyphicon-eye-open glyphicon" title="Visualização"></span>
                                    </div>

                                    <div class="col-xs-6 col-md-6 shares">
                                        <span class="num" title="Compatilhamento"> <?php echo $_post_['shares']; ?> </span>
                                        <span class="glyphicon-share glyphicon" title="Compatilhamento"></span>
                                    </div>
                                </div>

							<?php endif;?>

                                <div class="col-xs-5 col-md-3 social-media">
                                    <?php if( $_post_['status'] == 'publish') : ?>
                                        <a data-site="" class="facebook_share" href="http://www.facebook.com/sharer.php?u=<?php the_permalink(); ?>" target="_blank">
                                            <img src="<?php echo get_stylesheet_directory_uri(); ?>/assets/images/facebook.png" title="Facebook" alt="Compartilhar no Facebook">
                                        </a>
                                        <a data-site="" class="twitter_share" href="http://twitter.com/share?url=<?php the_permalink(); ?>&amp;text=<?php the_title_attribute(); ?>&amp;via=RedeHumanizaSUS" target="_blank">
                                            <img src="<?php echo get_stylesheet_directory_uri(); ?>/assets/images/twitter.png" title="Twitter" alt="Compartilhar no Twitter">
                                        </a>
                                        <a href="whatsapp://send?text=<?php the_title_attribute( 'after= ' ); ?><?php the_permalink(); ?>" data-text="<?php the_title_attribute(); ?>" data-href="<?php the_permalink(); ?>" target="_top" onclick="window.parent.null" class="hidden-md hidden-lg whatsapp_share">
                                            <img src="<?php echo get_stylesheet_directory_uri(); ?>/assets/images/whatsapp.png" title="Whatsapp" alt="Compartilhar no Whatsapp">
                                        </a>
                                    <?php endif;?>
                                    <a data-site="print" class="share_print share_link" href="#" onclick="window.print()">
                                        <img src="<?php echo get_stylesheet_directory_uri(); ?>/assets/images/print.png" title="Print" alt="Imprimir está página">
                                    </a>
                                </div>

                        </div> <!-- .share-wrap.col-md-5 -->

                    </div>
                </div>
            </div>

			<div class="clearfix"></div>
		</div>
	</div> <!-- .paine-heading -->

	<div class="panel-body content">  <?php the_content(); ?></div>

	<div class="panel-footer">
        <?php
        $attachments = get_posts(array(
            'post_type' => 'attachment',
            'posts_per_page' => -1,
            'post_parent' => $_post_id,
            'exclude'     => get_post_thumbnail_id()
        ));

        if (!empty($attachments)) {
            ?>
            <div class="post-attachments">
                <h4> Anexos </h4>
                <?php
                foreach ($attachments as $attachment):
                    $src = $attachment->guid;
                    if (wp_attachment_is_image($src)) {
                        $content = "<img src='$src' alt='Anexo do post' class='img-responsive'>";
                    } else {
                        $content = $attachment->post_title;
                    }
                    ?>
                    <a href="<?php echo $src; ?>" target="_blank"> <?php echo $content; ?> </a> <br />
                <?php
                endforeach;
                ?>
            </div>
            <?php
        } // has attachments

        if (has_post_ufmun($_post_id)) : ?>
            <div class="relacionado">
				<span>Post relacionado a: </span>
				<?php echo the_ufmun(); ?>
		    </div>
        <?php
        endif;

		if (has_tag()):
            ?>
			<div class="tags-content">
                <h5>Tags</h5>
				<span class="tags-list">
					<?php the_tags('', '', ''); ?>
				</span>
			</div>
		<?php endif; ?>
	</div>

    <?php
    if (is_user_logged_in())
        get_template_part("partes-templates/recommend-post"); ?>

</div><!-- .panel .panel-default -->

<?php
if ($_post_['status'] != 'draft' && $_post_['status'] != 'voting-expired' && ( comments_open() || get_comments_number() ) ) { ?>
	<div class="panel panel-default hidden-print">
		<div class="panel-footer panel-comentarios"> <?php comments_template(); ?> </div>
	</div>
<?php
}
