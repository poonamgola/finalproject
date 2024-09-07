from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import PasswordReset, PasswordResetConfirm, PasswordResetDone
from .views import search_profiles
# from .views import send_notification


urlpatterns = [
    path('account/@<str:username>/', views.userProfile, name='viewProfile'),
    path('update/@<str:username>/', views.updateProfile, name='updateProfile'),
    path('profile/@<str:username>/', views.profile, name='profile'),
    path('signup/', views.signUp, name='signUp'),
    path('signup-steps/<int:user_id>/', views.signUpSteps, name='signUpSteps'),
    path('login/', views.signIn, name='signin'),
    path('logout/', views.logOut, name='logout'),
    path('account-notification/', views.accountNotification, name='account_notification'),
    path('account-projects/', views.accountProjects, name='account_projects'),
    path('accountProject/update/<int:id>/', views.accountProject_update, name='accountProject_update'),
    path('account-projects_delete/<id>/', views.ProjectDelete, name="account-projects_delete"),
    path('search/', search_profiles, name='search_profiles'),
    path('message/', views.message, name='message'),
    path('start-conversation/<int:user_id>/', views.start_conversation, name='start_conversation'),
    path('chat/<int:thread_id>/', views.chat_view, name='chat_view'),
    path('chat/', views.messages_page,name='chat'),
    path('messages/', views.Messages, name='messages'),
    path('password_reset/', PasswordReset, name='password_reset'),
    path('password_reset/done/',PasswordResetDone, name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirm, name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password/password_reset_complete.html'), name='password_reset_complete'),
    # path('send_notification/', send_notification, name='send_notification'),
    # path('send_notification/', send_notification, name='send_notification'),
    # # path('notifications/', get_notifications, name='get_notifications'),
    # path('account-notification/', views.notifications_view, name='account-notification'),
    # path('account-notification/', views.notifications_view, name='account-notification'),
    path('send_notification/', views.send_notification, name='send_notification'),



   
]
