<?php 
/* Template Name: PageWithoutSidebar */ 
get_header();

    while ( have_posts() ) : 
        the_post();
        echo apply_filters( 'the_content', get_the_content() );
    endwhile;

get_footer();
?>