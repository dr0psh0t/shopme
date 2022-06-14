$(document).ready(function() {

    $("#success-alert").delay(4000).slideUp(200, function() {
        $(this).alert('close');
    });

    $("#searchButton").click(function(){
        let keyword = $("#keyword")[0].value;
        if (keyword != "") {
            $("#searchForm").submit();
        }
    });

    $("#clearButton").click(function(){
        $("#keyword")[0].value="";
    });

});