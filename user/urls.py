from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('logout/',views.userlogout, name='logout'),
    path('login/', views.login_page, name='login_page'),
    path('loginfn/', views.loginfn, name='loginfn'),
    path('new_password/<str:token>/',views.reset_password, name='new_password'),
    path('password_reset/',views.password_reset_request,name='password_reset'),
    path('registerfn/', views.registerfn, name='registerfn'),
    path('studentindex/', views.studentindex, name='studentindex'),
    path('adminindex/',views.adminindex, name='adminindex'), 
    path('user_profile/',views.user_profile,name='user_profile'),
    path('edit_profile/',views.edit_profile,name='edit_profile'),
    path('change_password/',views.change_password,name='change_password'),
    path('profile_view/',views.profile_view,name='profile_view'),
    path('delete_profile_picture/', views.delete_profile_picture, name='delete_profile_picture'),
    path('replace_profile_picture/', views.replace_profile_picture, name='replace_profile_picture'),
    
]
