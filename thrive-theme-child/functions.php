<?php

defined( 'TVE_EDITOR_URL' ) || define( 'TVE_EDITOR_URL', get_template_directory_uri() . '/architect/' );

add_action( 'wp_enqueue_scripts', function () {
	$parent_style = 'parent-style';

	wp_enqueue_style( $parent_style, get_template_directory_uri() . '/style.css' );
	wp_enqueue_style( 'child-style', get_stylesheet_directory_uri() . '/style.css', [ $parent_style ], wp_get_theme()->get( 'Version' ) );

	wp_enqueue_script( 'ajax-script', get_stylesheet_directory_uri() . '/js/fp_ajax_functions.js', array('jquery'), false, true );
	$rest_nonce = wp_create_nonce( 'wp_rest' );
	wp_localize_script( 'ajax-script', 'my_var', array( 'ajaxurl' => admin_url( 'admin-ajax.php' ), 'nonce' => $rest_nonce, ));
});

// add custom function here
require_once( 'inc/githuboauth.php' );
include 'inc/custom-functions.php';