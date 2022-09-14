$(document).ready(function () {
    $("form").submit(function (event) {
      var formData = {
        email: $("#email").val(),
        password: $("#password").val(),
      };
  
      $.ajax({
        type: "POST",
        url: "/api/login",
        data: formData,
      }).done(function (data) {
        $.ajax({
          type: "POST",
          url: "/api/test",
        }).done(function (data_) {
          console.log(data_)
        });
      });
  
      event.preventDefault();
    });
  });