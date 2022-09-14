var app = angular.module('postserviceApp', ['ngRoute']);

app.config(function ($routeProvider) {
    $routeProvider.when('/', {
        template: '<div class="app-login-email-wrapper">Почта : <input class="app-login-email-input" ng-model="email" /></div><br/><br/><div class="app-login-password-wrapper">Пароль : <input type="password" class="app-login-password-input" ng-model="password" /></div><br/><br/><input class="app-login-btn" type="button" value="Войти" ng-click="postdata(email, password)" />',
        controller: 'postserviceCtrl'
    }).otherwise({
        template: '',
        controller: 'routeCtrl'
    })
})

app.controller('routeCtrl', function($scope, $http, $location, $compile) {

    $scope.logout = function () {
        $('.btn-logout').remove();

        $http({url: 'https://putttt.pythonanywhere.com/api/logout', method: "POST"
            }).then(function (response) {
                if (response.data) {

                    if (response.data.status) {
                        $location.path('/');
                    }
                }
        }, function (response) {

                    $location.path('/');

                });
    };

    $scope.text = null;
    $http({
        url: 'https://putttt.pythonanywhere.com' + $location.path(),
        method: "GET",
    }).then(function (response) {
        if (response.data) {
            if (response.data.status) {
                let Element = angular.element(document.querySelector('ng-view'));
                let el = $compile(response.data.message)($scope);

                Element.append(el)
            } else {
                $location.path('/')
            }
        } else {
            console.log('Error')
        }
    })
})

app.controller('postserviceCtrl', function ($scope, $http, $location) {
    $scope.email = null;
    $scope.password = null;

    $scope.postdata = function (email, password) {
        var data = {
            email: email,
            password: password
        };

    $http({url: 'https://putttt.pythonanywhere.com/api/login', method: "POST",
    data: data, headers: {'Content-Type': 'application/json'}}).then(function (response) {
        if (response.data) {

            if (response.data.status) {
                console.log($location.path())
                $location.path('/supersecret')
            }

            $scope.msg = "Post Data Submitted Successfully!";
            $scope.statusval = response.status;
            $scope.statustext = response.statusText;
            $scope.headers = response.data.message

        }
}, function (response) {

    $scope.msg = "Service not Exists";
    $scope.statusval = response.status;
    $scope.statustext = response.statusText;
    $scope.headers = response.response;
        });
    };
});