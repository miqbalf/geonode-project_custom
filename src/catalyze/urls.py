from django.conf.urls import url, include
from django.urls import path

from rest_framework_simplejwt import views as jwt_views

from .views_api import (HomeView, #LogoutView, 
                        register_user, login_user, logout_user)

urlpatterns = [
    #adding jwt auth
    path('token/', 
          jwt_views.TokenObtainPairView.as_view(), 
          name ='token_obtain_pair'),
    path('token/refresh/', 
          jwt_views.TokenRefreshView.as_view(), 
          name ='token_refresh'),
    path('login/',
         login_user, name = 'login'
         ),
    path('register/', register_user, name='register_user'),
    
    path('logout/',logout_user, name='logout'),
    #path('logout/', LogoutView.as_view(), name ='logout'), 

    # adding example apply jwt and home
    path('jwt/', HomeView.as_view(), name ='jwt'),
    
    
]