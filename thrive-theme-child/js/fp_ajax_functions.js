jQuery(document).ready(function($) {
    $("#select_login_screen").click(function(){
        if($(this).is(":checked")){
            $(".fp_custom_login").css("display", "none");
            $(".fp_custom_registration").css("display", "block");
        }else{
            $(".fp_custom_registration").css("display", "none");
            $(".fp_custom_login").css("display", "block");
        }
    });

    $(".fp_forgot_pass").click(function(){
        $(".wc-forgot-pwd-form").css("display", "block");
        $(".fp_custom_login, .select_login_screen, .fp_custom_registration").css("display", "none");
    });

    $('#wp_login_form').on('submit', function(e){
        e.preventDefault();
        var formdata = $("#wp_login_form").serialize();

        $.ajax({
			method : 'POST',
			dataType : 'json',
			url : my_var.ajaxurl,
			data : formdata,
            success: function(response){
                if(response.redirect == 'true'){
                    window.location.replace(response.redirectUrl);
                }
            }
        })
    });
});