"""
URL configuration for univox project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from core.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('create-user/', create_user),
    path('delete-user/', delete_user),
    path('login/', login_user),
    path('logout/', logout_user),
    path('verifyemail/', verify_email),
    path('passwordresetreq/', reset_password_request),
    path('passwordresetvalidate/', reset_password_validate),
    path('passwordresetnewpass/', reset_password_chooseNew)
]
