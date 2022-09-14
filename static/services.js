(function () {
    'use strict';
    
    angular
        .module('app')
        .controller('HomeController', HomeController);
    
    HomeController.$inject = ['UserService', '$rootScope'];
    function HomeController(UserService, $rootScope) {
    
        $rootScope.bodylayout ='main_page_que';
        var vm = this;
    }
    })();