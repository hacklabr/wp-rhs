<?php 
// para esse template é necessário receber o valor da variável $curauth

$curauth = get_queried_object(); //(isset($_GET['author_name'])) ? get_user_by('slug', $author_name) : get_userdata(intval($author)); 
?>
<div class="tab-content">
    <div role="tabpanel" class="tab-pane fade in active" id="verDados">
        <div class="jumbotron">
        <?php
        if ($curauth && $curauth instanceof WP_User) {
            global $RHSUsers;
            global $RHSVote;
            global $RHSFollow;

            $RHSUsers = new RHSUsers($curauth->ID);
            $total_votos = $RHSVote->get_total_votes_by_author($curauth->ID);

            $total_followed = $RHSFollow->get_total_follows($curauth->ID, RHSFollow::FOLLOWED_KEY);
            $total_follow = $RHSFollow->get_total_follows($curauth->ID, RHSFollow::FOLLOW_KEY);
            $followed_posts = $RHSFollow->get_total_follows($curauth->ID, RHSFollow::FOLLOWED_POSTS_KEY);

            $total_posts = count_user_posts($curauth->ID);
            $profile_base = get_author_posts_url($curauth->ID);
            ?>
        <div class="avatar-user">
            <a href="<?php echo $profile_base; ?>">
                <?php echo get_avatar($RHSUsers->getUserId()); ?>
            </a>
        </div>
        <div class="info-user">
            <p class="nome-author">
                <a href="<?php echo $profile_base; ?>" style="color: black">
                    <?php echo $RHSUsers->get_user_data('display_name'); ?>
                </a>
                <?php if( is_user_logged_in() && is_author(get_current_user_id())) : ?>
                    <span class="btn-editar-user"><a class="btn btn-default" href="<?php echo home_url(RHSRewriteRules::PROFILE_URL ); ?>">EDITAR</a></span>
                <?php endif; ?>
            </p>
            <p class="localidade">
                <?php echo the_user_ufmun($RHSUsers->getUserId()); ?>
            </p>
            <p class="desde">
                <span>Membro desde:</span> <?php echo date("d/m/Y", strtotime(get_the_author_meta('user_registered', $curauth->ID))); ?>
                <?php if ($total_votos) { ?> &nbsp; | &nbsp;
                    <span class="contagem-desc-author">
                        <?php echo $total_votos . " " . ($total_votos == 1 ? "VOTO" : "VOTOS" ); ?>
                    </span>
                <?php } ?>

            </p>
            <div class="user-links">
                <div class="row">
                    <div class="col-xs-12">
                        <?php if (count_user_posts($curauth->ID)) { ?>
                            <div class="contagem first">
                                <a class="btn-link" href="<?php echo $profile_base; ?>">
                            <span class="contagem-valor-author">
                                <i class="fa fa-wpforms" aria-hidden="true"></i>
                                <?php echo $total_posts; ?>
                            </span>
                                    <span class="contagem-desc-author"><?php echo ($total_posts == 1 ? "POST" : "POSTS" );  ?></span>
                                </a>
                            </div>
                        <?php } ?>

                        <div class="contagem">
                            <a class="btn-link" href="<?php echo $profile_base . RHSRewriteRules::FOLLOW_URL; ?>">
                        <span class="contagem-valor-author">
                            <i class="fa fa-address-book" aria-hidden="true"></i>
                            <?php echo $total_follow ?>
                        </span>
                                <span class="contagem-desc-author">SEGUINDO</span>
                            </a>
                        </div>

                        <div class="contagem">
                            <a class="btn-link" href="<?php echo $profile_base . RHSRewriteRules::FOLLOWED_URL; ?>">
                        <span class="contagem-valor-author">
                            <i class="fa fa-users" aria-hidden="true"></i>
                            <?php echo $total_followed ?>
                        </span>
                                <span class="contagem-desc-author"><?php echo ($total_followed == 1 ? "SEGUIDOR" : "SEGUIDORES" );  ?></span>
                            </a>
                        </div>

                        <?php
                        if ($curauth->ID == get_current_user_id()) { ?>
                            <div class="contagem">
                                <a class="btn-link" href="<?php echo $profile_base . RHSRewriteRules::FOLLOWED_POSTS_URL; ?>">
                        <span class="contagem-valor-author">
                            <i class="fa fa-binoculars" aria-hidden="true"></i>
                            <?php echo $followed_posts; ?>
                        </span>
                                    <span class="contagem-desc-author"> POSTS SEGUIDOS </span>
                                </a>
                            </div>
                            <div class="contagem">
                                <a href="<?php echo $profile_base . RHSRewriteRules::USER_COMMENTS; ?>" class="btn-link">
                            <span class="contagem-valor-author">
                                <i class="fa fa-comments" aria-hidden="true"></i>
                                <span class="comments-count">
                                    <?php echo count(get_comments(['user_id' => get_current_user_id()])) ?>
                                </span>
                            </span>
                                    <span class="contagem-desc-author"> MEUS COMENTÁRIOS </span>
                                </a>
                            </div>
                        <?php } ?>
                    </div>
                </div>
            </div>
        </div>
        <span class="seguir-mensagem">
            <?php do_action('rhs_author_header_actions', $curauth->ID); ?>
        </span>
        <div class="clearfix"></div>
        <?php } else { ?>
            <div class="user-unknown">Esse usuário não existe!</div>
        <?php } ?>
        </div>
    </div>
</div>