$(document).ready(function() {

    $("input").change(function(e) {
        for (var i = 0; i < e.originalEvent.srcElement.files.length; i++) {
            var file = e.originalEvent.srcElement.files[i];

            var img = document.createElement("img");
            var reader = new FileReader();

            reader.onload = function(e) {
                $("#selectedPhoto")
                    .attr('src', e.target.result)
                    .width(100)
                    .height(100);
            };

            reader.readAsDataURL(file);
        }
    });

    $("#registrationSubmitBtn").click(function() {
        $.get('/ShopmeAdmin/IsEmailDuplicate', {email: $("#emailTxt")[0].value, id: $("#idField")[0].value},
            function(duplicate) {
                if (duplicate) {
                    new bootstrap.Modal(document.getElementById('emailAjaxModal')).show();
                } else {
                    $("#registrationForm").submit();
                }
        });
    });

});