$(document).ready(function() {

    $("#btnVerify").click(function() {

        $.post('/ShopmeAdmin/Verify', {
                username: $("#username")[0].value,
                code: $("#code")[0].value,
                _csrf: $("input[name=_csrf]").val()
            },
            function(response) {
                const res = JSON.parse(response);

                if (res['success']) {
                    $("#formLogin").submit();
                } else {
                    alert(res['msg']);
                }
            }
        );
    });

    $("#btnLogin").click(function() {

        $.post('/ShopmeAdmin/Authenticate', {
                username: $("#username")[0].value,
                password: $("#password")[0].value,
                _csrf: $("input[name=_csrf]").val()
            },
            function(response){
                const res = JSON.parse(response);

                if (res['success']) {
                    if (res['using2fa']) {

                        $("#divUsername")[0].style="display:none;";
                        $("#divPassword")[0].style="display:none;";
                        $("#btnLogin")[0].style="display:none;";
                        $("#registerLink")[0].style="display:none;";

                        $("#divCode")[0].style="display:block;";
                        $("#btnVerify")[0].style="display:block;";

                    } else {
                        $("#formLogin").submit();
                    }
                } else {
                    alert(res['msg']);
                }
            }
        );
    });

});